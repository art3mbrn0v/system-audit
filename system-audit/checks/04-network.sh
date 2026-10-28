# Network: firewall, listening sockets, connections, VPN, local databases.

audit_firewall() {
    subsection "Firewall Configuration & Active Rule Audit (UFW / firewalld / nftables / iptables)"
    local active=false

    if have ufw; then
        local ufw_out ufw_default
        ufw_out=$(ufw status verbose 2>/dev/null)
        if [[ "$ufw_out" == *"Status: active"* ]]; then
            active=true
            ufw_default=$(grep -i -m1 "Default:" <<< "$ufw_out")
            echo -e "  UFW Firewall Status: ${GREEN}ACTIVE${NC} (${ufw_default:-Default rules configured})"
        elif [[ -n "$ufw_out" ]]; then
            echo -e "  UFW Firewall Status: ${YELLOW}INACTIVE${NC}"
        fi
    fi

    if have firewall-cmd && [[ "$(firewall-cmd --state 2>/dev/null)" == "running" ]]; then
        active=true
        echo -e "  firewalld Status: ${GREEN}RUNNING${NC} (Active Zone: $(firewall-cmd --get-active-zones 2>/dev/null | head -n 1))"
    fi

    if have nft; then
        local nft_rules
        nft_rules=$(nft list ruleset 2>/dev/null)
        if [[ "$nft_rules" == *"table "* ]]; then
            active=true
            echo -e "  nftables Status: ${GREEN}ACTIVE${NC} ($(grep -c "chain " <<< "$nft_rules") filtering chain(s))"
        fi
    fi

    if have iptables; then
        local ipt_rules input_pol rule_count
        ipt_rules=$(iptables -L -n -v 2>/dev/null)
        if [[ -n "$ipt_rules" ]]; then
            # "Chain INPUT (policy DROP 0 packets, 0 bytes)"
            input_pol=$(grep -m1 "^Chain INPUT" <<< "$ipt_rules" | grep -oE 'policy [A-Z]+' | awk '{print $2}')
            rule_count=$(grep -cE '^[[:space:]]*[0-9]+' <<< "$ipt_rules")
            echo -e "  iptables IPv4 INPUT Policy : ${CYAN}${input_pol:-UNKNOWN}${NC} (${rule_count} rules)"
            if [[ "$input_pol" == "DROP" || "$input_pol" == "REJECT" ]]; then
                active=true
            elif [[ "$rule_count" -gt 0 ]]; then
                # Rules exist but the default INPUT policy is ACCEPT: configured, not necessarily protective
                active=true
                log_warn "iptables has ${rule_count} rule(s), but the INPUT policy is ${input_pol:-UNKNOWN}; verify that the rules really restrict inbound traffic."
            fi
        fi
    fi

    if [[ "$active" == true ]]; then
        log_pass "Active packet filtering firewall verified."
    else
        log_crit "NO ACTIVE FIREWALL: no ufw/firewalld/nftables/iptables filtering found - all inbound connections are unfiltered."
    fi
}

audit_listening_sockets() {
    subsection "Open Listening TCP/UDP Ports & Associated Processes (ss -tulpn)"
    have ss || return 0
    local ss_output
    ss_output=$(ss -tulpn 2>/dev/null)
    if [[ $(count_lines "$ss_output") -le 1 ]]; then
        log_pass "No active listening TCP/UDP sockets found."
        return 0
    fi

    # Names and IPs of virtual bridges (libvirt virbr*, docker*, br-*): reachable only from VMs/containers
    local bridge_ifaces bridge_ips bi
    bridge_ifaces=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(virbr|docker|br-|lxcbr|podman|cni)')
    bridge_ips=$(for bi in $bridge_ifaces; do ip -o addr show dev "$bi" 2>/dev/null | awk '{split($4, a, "/"); print a[1]}'; done)

    local public_count=0 local_count=0 bridge_count=0 risky=()
    local netid local_addr proc port addr scope proc_name
    echo -e "  ${CYAN}Active Listening Network Sockets:${NC}"
    # Netid State Recv-Q Send-Q Local:Port Peer:Port Process
    while read -r netid _ _ _ local_addr _ proc; do
        [[ -z "$local_addr" ]] && continue
        port="${local_addr##*:}"
        addr="${local_addr%:*}"
        proc_name="[Unknown/Root]"
        [[ "$proc" =~ users:\(\(\"([^\"]+)\" ]] && proc_name="${BASH_REMATCH[1]}"
        [[ "$proc" =~ pid=([0-9]+) ]] && proc_name+=" (PID: ${BASH_REMATCH[1]})"

        if [[ "$addr" =~ ^127\. || "$addr" == "[::1]" ]]; then
            scope="Localhost"
            local_count=$((local_count + 1))
        elif [[ "$addr" == *%* || "$addr" =~ ^\[fe80: ]] && [[ "$port" =~ ^(546|68)$ ]]; then
            # DHCP client bound to a link-local address: not a reachable service
            scope="Link-local"
            local_count=$((local_count + 1))
        elif { [[ "$addr" == *%* ]] && grep -qxF "${addr##*%}" <<< "$bridge_ifaces"; } \
             || grep -qxF "$(tr -d '[]' <<< "${addr%%\%*}")" <<< "$bridge_ips"; then
            scope="VM-bridge"
            bridge_count=$((bridge_count + 1))
        else
            scope="Public"
            public_count=$((public_count + 1))
            case "$port" in
                21) risky+=("FTP (port 21, cleartext credentials) - ${proc_name}") ;;
                23) risky+=("Telnet (port 23, cleartext shell) - ${proc_name}") ;;
                25) risky+=("SMTP (port 25, plaintext mail relay) - ${proc_name}") ;;
                69) risky+=("TFTP (port 69, unauthenticated file transfer) - ${proc_name}") ;;
                161|162) risky+=("SNMP (port ${port}, unencrypted management) - ${proc_name}") ;;
                512|513|514) risky+=("Legacy r-services (port ${port}) - ${proc_name}") ;;
                3306|5432|6379|27017|11211|9200) risky+=("Database/cache port ${port} on a public interface - ${proc_name}") ;;
            esac
        fi
        printf "    - %-5s | %-20s | Port %-5s | Scope: %-10s | Process: %s\n" "$netid" "$addr" "$port" "$scope" "$proc_name"
    done < <(tail -n +2 <<< "$ss_output")

    log_pass "Listening sockets: ${public_count} on all/public interfaces, ${bridge_count} VM/container-bridge-only, ${local_count} localhost-only."
    [[ ${#risky[@]} -gt 0 ]] && log_crit "Risky / unencrypted services listening on public interfaces:" "${risky[@]}"

    if matches ':5355[[:space:]].*systemd-resolve' "$ss_output"; then
        log_warn "LLMNR (UDP/TCP 5355) is active in systemd-resolved. Disable with LLMNR=no in /etc/systemd/resolved.conf.d/ unless needed."
    fi
    if matches ':5353[[:space:]].*avahi' "$ss_output"; then
        log_warn "avahi-daemon (mDNS, UDP 5353) is listening. Disable it if you do not need network printers / Chromecast / .local discovery."
    fi
    if matches ':(500|4500)[[:space:]].*charon' "$ss_output"; then
        log_info "strongSwan (charon) listens on IKE ports 500/4500. Expected if you use IPsec/IKEv2; otherwise: systemctl disable --now strongswan-starter strongswan"
    fi
}

audit_established_connections() {
    subsection "Active Established Outbound Network Connections"
    have ss || return 0
    local conns
    conns=$(ss -tunp state established 2>/dev/null | grep -v '127\.0\.0\.1' | grep -v '::1')
    if [[ $(count_lines "$conns") -gt 1 ]]; then
        sed 's/^/  /' <<< "$conns"
        log_pass "Listed $(( $(count_lines "$conns") - 1 )) established connection(s) to other hosts."
    else
        log_pass "No established connections to external hosts."
    fi
}

audit_vpn() {
    subsection "Active VPN, Mesh & Tunneling Interfaces"
    local vpn_ifaces
    vpn_ifaces=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(tun[0-9]|tap[0-9]|wg[0-9]|tailscale|zerotier|zt)' | paste -sd' ' -)
    if [[ -n "$vpn_ifaces" ]]; then
        echo -e "  Active VPN / mesh interfaces: ${CYAN}${vpn_ifaces}${NC}"
    else
        echo -e "  No active VPN/mesh interfaces (WireGuard, OpenVPN, Tailscale, ZeroTier)."
    fi

    local files=() vfile mode bad=()
    while read -r vfile; do files+=("$vfile"); done < <(find /etc/wireguard /etc/openvpn -type f 2>/dev/null)
    [[ ${#files[@]} -gt 0 ]] || return 0

    for vfile in "${files[@]}"; do
        mode=$(file_mode "$vfile")
        if [[ "$(head -c 2 "$vfile" 2>/dev/null)" == "#!" ]]; then
            # Hook scripts (e.g. openvpn update-resolv-conf) are code, not secrets:
            # executable by the owner and not writable by group/others
            if ! mode_has "$mode" 100 || mode_has "$mode" 022; then
                bad+=("${vfile} (hook script, mode ${mode}, expected 755)")
            fi
        elif [[ ! "$mode" =~ ^(600|400|640)$ ]]; then
            bad+=("${vfile} (mode ${mode}, expected 600)")
        fi
    done
    if [[ ${#bad[@]} -gt 0 ]]; then
        log_warn "VPN configuration files with wrong permissions:" "${bad[@]}"
    else
        log_pass "VPN configuration files (${#files[@]}) have correct permissions (configs 600, hook scripts 755)."
    fi
}

# Local database services that accept logins without a password
audit_databases() {
    subsection "Database Unauthenticated & Passwordless Access Audit"
    local listen detected=0
    listen=$(ss -tuln 2>/dev/null)

    if have mysql || have mariadb || matches ":3306[[:space:]]" "$listen"; then
        detected=$((detected + 1))
        local mysql_cmd
        mysql_cmd=$(command -v mysql || command -v mariadb)
        if [[ -z "$mysql_cmd" ]]; then
            log_info "MySQL/MariaDB port 3306 is open, but no client is installed to test it."
        elif "$mysql_cmd" -h 127.0.0.1 -u root --password="" -e "SELECT 1;" &>/dev/null; then
            log_crit "MySQL/MariaDB allows passwordless 'root' login over TCP (127.0.0.1)!"
        elif "$mysql_cmd" -h 127.0.0.1 -u anonymous --password="" -e "SELECT 1;" &>/dev/null; then
            log_crit "MySQL/MariaDB allows passwordless 'anonymous' login over TCP!"
        else
            log_pass "MySQL/MariaDB requires password authentication over TCP."
        fi
    fi

    if have psql || matches ":5432[[:space:]]" "$listen"; then
        detected=$((detected + 1))
        if have psql && PGPASSWORD="" psql -h 127.0.0.1 -U postgres -c "SELECT 1;" &>/dev/null; then
            log_crit "PostgreSQL allows passwordless 'postgres' login over TCP (127.0.0.1)!"
        else
            log_pass "PostgreSQL requires password authentication over TCP."
        fi
        local trust_rules
        trust_rules=$(find /etc/postgresql /var/lib/pgsql -name "pg_hba.conf" -exec grep -HEi "^[[:space:]]*(host|local)[[:space:]]+.*trust" {} + 2>/dev/null)
        [[ -n "$trust_rules" ]] && log_warn "PostgreSQL 'trust' authentication rules (no password):" "$trust_rules"
    fi

    if have redis-cli || matches ":6379[[:space:]]" "$listen"; then
        detected=$((detected + 1))
        if have redis-cli && [[ "$(redis-cli -h 127.0.0.1 -p 6379 PING 2>/dev/null)" == "PONG" ]]; then
            log_crit "Redis (127.0.0.1:6379) answers without a password!"
        else
            log_pass "Redis requires authentication (requirepass configured)."
        fi
    fi

    if have mongosh || have mongo || matches ":27017[[:space:]]" "$listen"; then
        detected=$((detected + 1))
        local mongo_cmd mongo_out=""
        mongo_cmd=$(command -v mongosh || command -v mongo)
        [[ -n "$mongo_cmd" ]] && mongo_out=$("$mongo_cmd" --host 127.0.0.1 --port 27017 --eval "db.adminCommand('ping')" --quiet 2>/dev/null)
        if [[ "$mongo_out" == *ok* ]]; then
            log_crit "MongoDB (127.0.0.1:27017) accepts administrative commands without authentication!"
        else
            log_pass "MongoDB requires authentication for database commands."
        fi
    fi

    if have memcached || matches ":11211[[:space:]]" "$listen"; then
        detected=$((detected + 1))
        if have nc && [[ -n "$(echo "stats" | nc -w 2 127.0.0.1 11211 2>/dev/null | grep -i "STAT")" ]]; then
            log_warn "Memcached (127.0.0.1:11211) is accessible without authentication."
        else
            log_pass "Memcached port 11211 is protected or inactive."
        fi
    fi

    if matches ":9200[[:space:]]" "$listen"; then
        detected=$((detected + 1))
        local es_out
        es_out=$(curl -s -m 2 http://127.0.0.1:9200/ 2>/dev/null)
        if [[ "$es_out" == *cluster_name* || "$es_out" == *lucene* ]]; then
            log_crit "Elasticsearch (127.0.0.1:9200) answers HTTP requests without authentication!"
        else
            log_pass "Elasticsearch requires HTTP authentication."
        fi
    fi

    if [[ "$detected" -eq 0 ]]; then
        log_pass "No local database services (MySQL, PostgreSQL, Redis, MongoDB, Memcached, Elasticsearch) detected."
    fi
}

section_network() {
    audit_firewall
    audit_listening_sockets
    audit_established_connections
    audit_vpn
    audit_databases
}

register_section network "Network Security: Firewall, Listening Ports, Databases & VPN" section_network
