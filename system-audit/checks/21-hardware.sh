# Hardware devices, removable media, Wi-Fi and the local network.

audit_devices() {
    subsection "USB, Storage & PCI Devices"
    if have lsusb; then
        local usb suspicious
        usb=$(lsusb 2>/dev/null)
        echo "  USB devices: $(count_lines "$usb")"
        sed 's/^/    /' <<< "$usb"
        suspicious=$(grep -Ei "rubber|ducky|badusb|keysmith|keystroke|wireless[ _]?sniffer|packet[ _]?sniffer|wifi[ _]?pineapple|lan[ _]?turtle|bash[ _]?bunny|pwnagotchi" <<< "$usb")
        [[ -n "$suspicious" ]] && log_crit "USB devices matching known attack-tool names (keystroke injection / sniffing):" "$suspicious"
    fi
    have lspci && lspci 2>/dev/null | grep -Ei "VGA|Network|Ethernet|Wireless|Thunderbolt|RAID|SATA|NVMe" | head -n 10 | sed 's/^/    /'

    have lsblk || return 0
    lsblk -o NAME,SIZE,TYPE,TRAN,RM,MOUNTPOINT 2>/dev/null | sed 's/^/  /'
    local dev mnt rm tran opts no_nosuid=() exec_allowed=()
    while read -r dev; do
        mnt=$(findmnt -rn -o TARGET "/dev/$dev" 2>/dev/null | head -n 1)
        [[ -n "$mnt" ]] || continue
        rm=$(lsblk -ndo RM "/dev/$dev" 2>/dev/null | tr -d ' ')
        tran=$(lsblk -ndo TRAN "/dev/$dev" 2>/dev/null | tr -d ' ')
        [[ "$rm" == "1" || "$tran" =~ ^(usb|mmc)$ || "$dev" == mmcblk* ]] || continue
        opts=$(findmnt -n -o OPTIONS "$mnt" 2>/dev/null)
        if [[ "$opts" != *nosuid* ]]; then
            no_nosuid+=("${mnt} (/dev/${dev}): ${opts}")
        elif [[ "$opts" != *noexec* ]]; then
            exec_allowed+=("${mnt} (/dev/${dev})")
        fi
    done < <(lsblk -rno NAME 2>/dev/null)
    [[ ${#no_nosuid[@]} -gt 0 ]] && log_warn "Removable media mounted without 'nosuid' (a SUID binary on it would run as its owner):" "${no_nosuid[@]}"
    [[ ${#exec_allowed[@]} -gt 0 ]] && log_info "Removable media mounted nosuid but executable (fine for data cards; add noexec if you never run programs from them):" "${exec_allowed[@]}"
}

audit_bluetooth() {
    subsection "Bluetooth"
    if ! have bluetoothctl; then
        echo "  bluetoothctl not available."
        return 0
    fi
    local bt powered discoverable
    bt=$(bluetoothctl show 2>/dev/null)
    if [[ -z "$bt" ]]; then
        echo "  No Bluetooth controller active."
        return 0
    fi
    powered=$(awk '/Powered:/ {print $2; exit}' <<< "$bt")
    discoverable=$(awk '/Discoverable:/ {print $2; exit}' <<< "$bt")
    echo -e "  Powered: ${CYAN}${powered:-unknown}${NC}, discoverable: ${CYAN}${discoverable:-unknown}${NC}"
    if [[ "$discoverable" == "yes" ]]; then
        log_warn "Bluetooth adapter is discoverable by nearby devices."
    else
        log_pass "Bluetooth adapter is not discoverable."
    fi
}

audit_wifi_and_lan() {
    subsection "Wi-Fi & Local Network"
    local route gw iface cidr="" network=""
    route=$(ip route show default 2>/dev/null | head -n 1)
    if [[ -n "$route" ]]; then
        gw=$(awk '{print $3}' <<< "$route")
        iface=$(awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' <<< "$route")
        cidr=$(ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4; exit}')
        network=$(ip -4 route show dev "$iface" scope link proto kernel 2>/dev/null | awk '{print $1; exit}')
        echo -e "  Interface ${CYAN}${iface}${NC}, address ${CYAN}${cidr}${NC}, gateway ${CYAN}${gw}${NC}"
    else
        echo "  No default route."
    fi

    if have nmcli; then
        # Terse output for logic: "IN-USE:SECURITY:SSID" (SSID last: it may contain ':'); empty/'--' = open
        local wifi current open_count
        wifi=$(nmcli -t -f IN-USE,SECURITY,SSID dev wifi 2>/dev/null)
        if awk -F: '$1 == "*" {found = 1} END {exit !found}' <<< "$wifi"; then
            current=$(awk -F: '$1 == "*" {print $2; exit}' <<< "$wifi")
            echo -e "  Connected Wi-Fi: ${CYAN}$(awk -F: '$1 == "*" {sub(/^[^:]*:[^:]*:/, ""); print; exit}' <<< "$wifi")${NC} (${current:-open})"
            case "$current" in
                ""|--)  log_crit "Connected to an OPEN (unencrypted) Wi-Fi network: traffic can be intercepted." ;;
                *WEP*)  log_crit "Connected to a WEP Wi-Fi network: the encryption is broken." ;;
                *WPA3*|*WPA2*) log_pass "Connected Wi-Fi uses ${current}." ;;
                *WPA1*) log_warn "Connected Wi-Fi uses obsolete WPA1." ;;
            esac
        fi
        open_count=$(awk -F: '$2 == "--" || $2 == ""' <<< "$wifi" | grep -c .)
        echo "  Wi-Fi networks in range: $(count_lines "$wifi") (open: ${open_count})"
    fi

    [[ -n "$cidr" ]] || return 0
    # Scan the real local network, but never more than a /24 around our address
    local prefix=${cidr#*/} target="${network:-$cidr}" hosts
    [[ "$prefix" =~ ^[0-9]+$ && "$prefix" -lt 24 ]] && target="${cidr%/*}/24"
    if have nmap && slow_scan "LAN host scan (nmap)"; then
        echo "  Scanning ${target} for active hosts..."
        hosts=$(nmap -sn --host-timeout 3s "$target" 2>/dev/null | awk '/Nmap scan report/ {sub(/^Nmap scan report for /, ""); print}')
        [[ -n "$hosts" ]] && log_info "Active hosts on the local network ($(count_lines "$hosts")):" "$hosts"
    else
        log_info "Neighbours from the ARP cache:" "$(ip neighbor show 2>/dev/null | grep -v FAILED)"
    fi
}

section_hardware_and_lan() {
    audit_devices
    audit_bluetooth
    audit_wifi_and_lan
}

register_section hardware "Hardware Devices, Wi-Fi Security & Local Network Hosts" section_hardware_and_lan
