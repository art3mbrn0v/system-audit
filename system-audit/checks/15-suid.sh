# SUID/SGID executables and world-writable system files.

section_suid() {
    subsection "SUID/SGID Files Outside System Paths"
    local found sfile owner_pkg pkg_owned=() unowned=()
    found=$(scan_find /tmp /var/tmp /dev/shm /home /opt /var/www /srv -- -type f \( -perm -4000 -o -perm -2000 \))
    while read -r sfile; do
        [[ -n "$sfile" ]] || continue
        owner_pkg=$(pkg_owner "$sfile")
        if [[ -n "$owner_pkg" ]]; then pkg_owned+=("${sfile} (package ${owner_pkg})"); else unowned+=("$sfile"); fi
    done <<< "$found"
    [[ ${#pkg_owned[@]} -gt 0 ]] && log_info "SUID/SGID helpers shipped by packages outside /usr (expected, e.g. browser sandboxes):" "${pkg_owned[@]}"
    if [[ ${#unowned[@]} -gt 0 ]]; then
        log_crit "SUID/SGID files not owned by any package in temporary/user/web paths:" "${unowned[@]}"
    else
        log_pass "No foreign SUID/SGID files in /tmp, /dev/shm, /home, /opt, /var/www, /srv."
    fi

    subsection "SUID Binaries in System Paths (GTFOBins privilege escalation)"
    local suid_files gtfobins
    local gtfobins_re='^(find|vim|vi|bash|sh|python|python3|perl|php|awk|less|more|nmap|env|gdb|strace|tcpdump|tar|cp|mv|base64|cpulimit|docker|date|dd|flock|ionice|nice|taskset|time|timeout|watch|xargs|zip|zsh)$'
    suid_files=$(find /usr/bin /usr/sbin /bin /sbin /usr/lib /usr/libexec -type f -perm -4000 2>/dev/null | sort -u)
    echo -e "  SUID binaries in system paths: ${CYAN}$(count_lines "$suid_files")${NC}"
    gtfobins=$(while read -r sfile; do [[ -n "$sfile" && "${sfile##*/}" =~ $gtfobins_re ]] && echo "$sfile"; done <<< "$suid_files")
    if [[ -n "$gtfobins" ]]; then
        log_crit "SUID set on binaries that give a root shell (GTFOBins):" "$gtfobins"
    else
        log_pass "No GTFOBins shell-escape binary has the SUID bit."
    fi

    subsection "World-Writable Files in System Directories"
    local ww_files
    ww_files=$(scan_find /etc /var /opt /usr /boot -- -type f -perm -0002)
    if [[ -n "$ww_files" ]]; then
        log_crit "World-writable files in system directories (any user can modify them):" "$ww_files"
    else
        log_pass "No world-writable files in /etc, /var, /opt, /usr, /boot."
    fi
}

register_section suid "SUID / SGID Executables & World-Writable System Files" section_suid
