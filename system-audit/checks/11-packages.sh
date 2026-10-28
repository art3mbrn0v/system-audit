# Package repositories, kernel packages, recommended security tools, held packages.

audit_repositories() {
    subsection "Package Repositories (Official vs Third-Party)"
    local urls official=() third_party=() url domain
    case "$PKG_MGR" in
        apt)
            local files=()
            [[ -f /etc/apt/sources.list ]] && files+=(/etc/apt/sources.list)
            mapfile -t -O "${#files[@]}" files < <(find /etc/apt/sources.list.d -type f \( -name "*.list" -o -name "*.sources" \) 2>/dev/null | sort)
            # One-line "deb URL ..." entries and deb822 "URIs: URL [URL...]" fields
            [[ ${#files[@]} -gt 0 ]] && urls=$(cat "${files[@]}" 2>/dev/null \
                | grep -E '^[[:space:]]*(deb|deb-src)[[:space:]]|^[[:space:]]*URIs:' \
                | grep -oE '(https?|ftp)://[^ "]+' | sort -u)
            local official_re='(^|\.)(debian\.org|ubuntu\.com|kali\.org|raspbian\.org|linuxmint\.com)$'
            ;;
        dnf)
            urls=$(grep -hEi '^[[:space:]]*(baseurl|metalink|mirrorlist)[[:space:]]*=' /etc/yum.repos.d/*.repo 2>/dev/null \
                   | cut -d= -f2- | tr -d ' ' | sort -u)
            local official_re='(^|\.)(fedoraproject\.org|redhat\.com|centos\.org|almalinux\.org|rockylinux\.org)$'
            ;;
        *) return 0 ;;
    esac

    while read -r url; do
        [[ -n "$url" ]] || continue
        domain=$(awk -F/ '{print $3}' <<< "$url")
        if [[ "$domain" =~ $official_re ]]; then official+=("$url"); else third_party+=("$url"); fi
    done <<< "$urls"
    [[ ${#official[@]} -gt 0 ]] && echo "  Official repositories:" && print_details "${official[@]}"
    if [[ ${#third_party[@]} -gt 0 ]]; then
        log_warn "Third-party package repositories (their packages run as root on install - keep only trusted vendors):" "${third_party[@]}"
    else
        log_pass "All ${#official[@]} package repositories belong to the distribution."
    fi
}

audit_kernel_packages() {
    subsection "Kernel Updates & Reboot Status"
    local running kernel_updates
    running=$(uname -r)
    echo -e "  Running kernel: ${CYAN}${running}${NC} ($(uname -v))"

    case "$PKG_MGR" in
        apt) kernel_updates=$(pkg_upgrades | awk -F'\t' '$1 ~ /^linux-(image|headers|generic|amd64|arm64)/ {print $1}') ;;
        dnf) kernel_updates=$(pkg_upgrades | awk -F'\t' '$1 ~ /^kernel(-core|-modules)?$/ {print $1}') ;;
    esac
    if [[ -n "$kernel_updates" ]]; then
        log_warn "Kernel update available (install it and reboot):" "$kernel_updates"
    elif [[ -n "$PKG_MGR" ]]; then
        log_pass "Kernel is up to date in the repository."
    fi

    if [[ -f /var/run/reboot-required ]]; then
        log_warn "Reboot required (/var/run/reboot-required) - updated components are not active yet:" "$(cat /var/run/reboot-required.pkgs 2>/dev/null)"
    elif [[ "$PKG_MGR" == "dnf" ]]; then
        local newest
        newest=$(rpm -q kernel-core --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V | tail -n 1)
        if [[ -n "$newest" && "$running" != "$newest"* ]]; then
            log_warn "Reboot required: running kernel ${running} differs from the newest installed ${newest}."
        fi
    fi

    local uptime_days
    uptime_days=$(awk '{printf "%d", $1 / 86400}' /proc/uptime 2>/dev/null)
    if [[ "${uptime_days:-0}" -gt 90 ]]; then
        log_warn "Uptime is ${uptime_days} days: kernel fixes installed since the last boot are not active."
    fi
}

audit_recommended_packages() {
    subsection "Recommended Security Packages"
    local recommended=() pkg missing=() upgradable
    case "$PKG_MGR" in
        apt)
            recommended=(ufw auditd apparmor unattended-upgrades clamav chkrootkit needrestart debsums lynis)
            # fail2ban only makes sense when an SSH daemon is installed
            [[ -f /etc/ssh/sshd_config ]] && recommended+=(fail2ban)
            ;;
        dnf) recommended=(fail2ban firewalld audit clamav chkrootkit policycoreutils crypto-policies) ;;
        *)   return 0 ;;
    esac
    upgradable=$(pkg_upgrades | cut -f1)
    for pkg in "${recommended[@]}"; do
        if ! pkg_installed "$pkg"; then
            missing+=("$pkg")
        elif grep -qxF "$pkg" <<< "$upgradable"; then
            echo -e "  - ${pkg}: installed, ${YELLOW}update available${NC}"
        else
            echo -e "  - ${pkg}: installed"
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_info "Recommended security packages not installed: ${missing[*]}"
    else
        log_pass "All recommended security packages are installed."
    fi

    if have needrestart; then
        local svcs svc
        svcs=$(needrestart -b 2>/dev/null | awk '/^NEEDRESTART-SVC:/ {print $2}')
        if [[ -z "$svcs" ]]; then
            log_pass "needrestart: no service runs outdated binaries/libraries."
        else
            log_warn "Services still running outdated binaries/libraries after updates (restart them):" "$svcs"
            if [[ "$AUTO_RESTART_SERVICES" == true ]]; then
                while read -r svc; do
                    restart_service "$svc" "outdated binary/library after package update"
                done <<< "$svcs"
            fi
        fi
    fi
}

audit_held_packages() {
    subsection "Pinned / Held Package Versions"
    local pins="" pkg inst cand outdated=() count=0
    if [[ "$PKG_MGR" == "apt" ]]; then
        pins=$( { apt-mark showhold 2>/dev/null
                  grep -hEi "^[[:space:]]*Package:" /etc/apt/preferences /etc/apt/preferences.d/* 2>/dev/null | awk '{print $2}' | grep -v '\*'
                } | sed '/^[[:space:]]*$/d' | sort -u)
        while read -r pkg; do
            [[ -n "$pkg" ]] || continue
            count=$((count + 1))
            local policy
            policy=$(apt-cache policy "$pkg" 2>/dev/null)
            inst=$(awk '/Installed:/ {print $2; exit}' <<< "$policy")
            cand=$(awk '/Candidate:/ {print $2; exit}' <<< "$policy")
            echo -e "  - ${CYAN}${pkg}${NC}: installed ${inst:-none}, candidate ${cand:-unknown}"
            [[ -n "$cand" && "$inst" != "(none)" && "$inst" != "$cand" ]] && outdated+=("${pkg}: ${inst} -> ${cand}")
        done <<< "$pins"
    elif [[ "$PKG_MGR" == "dnf" && -f /etc/dnf/plugins/versionlock.list ]]; then
        pins=$(grep -v '^[[:space:]]*#' /etc/dnf/plugins/versionlock.list | sed -E 's/-[0-9].*$//' | sed '/^$/d' | sort -u)
        while read -r pkg; do
            [[ -n "$pkg" ]] || continue
            count=$((count + 1))
            inst=$(rpm -q --queryformat '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null)
            cand=$(pkg_upgrades | awk -F'\t' -v p="$pkg" '$1 == p {split($2, a, " "); print a[1]; exit}')
            echo -e "  - ${CYAN}${pkg}${NC}: installed ${inst:-none}${cand:+, available ${cand}}"
            [[ -n "$cand" ]] && outdated+=("${pkg}: ${inst} -> ${cand}")
        done <<< "$pins"
    fi

    if [[ ${#outdated[@]} -gt 0 ]]; then
        log_warn "Held/pinned packages kept below the available version (they miss security fixes):" "${outdated[@]}"
    elif [[ "$count" -gt 0 ]]; then
        log_pass "Held/pinned packages (${count}) are at the repository version."
    else
        echo "  No held or pinned packages."
    fi
}

section_packages() {
    audit_repositories
    audit_kernel_packages
    audit_recommended_packages
    audit_held_packages
}

register_section packages "Package Repositories, Kernel & Recommended Security Packages" section_packages
