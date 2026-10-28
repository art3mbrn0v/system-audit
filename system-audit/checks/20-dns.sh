# DNS resolvers, encrypted DNS and /etc/hosts.

section_dns() {
    subsection "Resolver Configuration"
    local resolv=/etc/resolv.conf
    if [[ -L "$resolv" ]]; then
        echo -e "  /etc/resolv.conf -> ${CYAN}$(readlink -f "$resolv")${NC} (managed by the resolver service)"
    elif [[ -f "$resolv" ]]; then
        local mode
        mode=$(file_mode "$resolv")
        echo -e "  /etc/resolv.conf: static file, mode ${mode}"
        mode_has "$mode" 022 && log_warn "/etc/resolv.conf is writable by non-root users (mode ${mode}): DNS can be redirected."
    else
        log_warn "/etc/resolv.conf is missing: name resolution will fail."
    fi

    local ns kind
    while read -r _ ns _; do
        [[ -n "$ns" ]] || continue
        case "$ns" in
            127.*|::1)                    kind="local stub resolver" ;;
            192.168.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) kind="LAN router" ;;
            1.1.1.1|1.0.0.1)              kind="Cloudflare" ;;
            8.8.8.8|8.8.4.4)              kind="Google" ;;
            9.9.9.9|149.112.112.112)      kind="Quad9" ;;
            *)                            kind="upstream" ;;
        esac
        echo -e "  nameserver ${CYAN}${ns}${NC} (${kind})"
    done < <(grep '^nameserver' "$resolv" 2>/dev/null)

    subsection "Encrypted DNS & DNSSEC"
    if have resolvectl; then
        local status proto dot dnssec
        status=$(resolvectl status 2>/dev/null)
        proto=$(awk '/^Global/ {g = 1; next} /^Link / {g = 0} g && /Protocols:/ {print; exit}' <<< "$status")
        [[ -z "$proto" ]] && proto=$(grep -m1 'Protocols:' <<< "$status")
        dot=$(grep -oE '[+-]DNSOverTLS' <<< "$proto" | head -n 1)
        dnssec=$(grep -oE 'DNSSEC=[^ ]+' <<< "$proto" | head -n 1)
        echo -e "  systemd-resolved: ${CYAN}${dot:-DoT not reported}${NC}, ${CYAN}${dnssec:-DNSSEC not reported}${NC}"
        if [[ "$dot" == "+DNSOverTLS" ]]; then
            log_pass "DNS-over-TLS is active in systemd-resolved."
        else
            # Encrypted DNS matters on untrusted networks; a home router usually cannot offer DoT
            log_info "DNS queries are sent unencrypted (no DNS-over-TLS). Consider DoT on untrusted networks."
        fi
    fi
    # dnsmasq (e.g. libvirt's) is a plain-text forwarder; unbound counts only with TLS upstreams
    local proxies=(cloudflared dnscrypt-proxy stubby adguardhome) proxy running=""
    grep -rqsE '^[[:space:]]*forward-tls-upstream:[[:space:]]*yes' /etc/unbound/ && proxies+=(unbound)
    for proxy in "${proxies[@]}"; do
        pgrep -x "$proxy" &>/dev/null && running+="${proxy} "
    done
    [[ -n "$running" ]] && log_pass "Encrypted DNS proxy running: ${running}"

    subsection "/etc/hosts Overrides & Resolution Test"
    local custom test_ip
    custom=$(grep -vE '^[[:space:]]*#|localhost|127\.0\.0\.1|127\.0\.1\.1|::1|fe00::0|ff02::' /etc/hosts 2>/dev/null | grep -v '^[[:space:]]*$')
    if [[ -n "$custom" ]]; then
        log_warn "Custom /etc/hosts entries (verify that no update or security domains are redirected):" "$custom"
    else
        log_pass "No custom entries in /etc/hosts."
    fi
    test_ip=$(getent ahosts google.com 2>/dev/null | awk '{print $1; exit}')
    if [[ -n "$test_ip" ]]; then
        echo "  DNS resolution works (google.com -> ${test_ip})."
    else
        log_warn "DNS resolution test for google.com failed."
    fi
}

register_section dns "DNS Resolvers, Encrypted DNS (DoH/DoT) & /etc/hosts" section_dns
