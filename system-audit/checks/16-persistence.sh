# Persistence: cron jobs, systemd timers, at jobs.

section_persistence() {
    # Download-and-execute, reverse shells, encoded payloads, staging dirs. Plain `eval`,
    # `nohup` or /tmp usage is common in legitimate package cron scripts.
    local suspicious_re='(curl|wget)[^|#]*\|[[:space:]]*(ba|z)?sh|/dev/tcp/|base64[[:space:]]+(-d|--decode)|(^|[[:space:]=])/(dev/shm|var/tmp)/|python[0-9.]*[[:space:]]+-c|nc[[:space:]]+-e|chmod[[:space:]]+[0-7]*777'
    local foreign=() package_owned=() user uid home shell jobs hits

    subsection "Cron Jobs"
    while IFS=: read -r user uid home shell; do
        jobs=$(crontab -u "$user" -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
        [[ -n "$jobs" ]] || continue
        echo -e "  ${CYAN}crontab of ${user}:${NC}"
        sed 's/^/    /' <<< "$jobs"
        hits=$(grep -E "$suspicious_re" <<< "$jobs")
        [[ -n "$hits" ]] && foreign+=("crontab ${user}: ${hits}")
    done < <(all_accounts)

    if [[ -f /etc/crontab ]]; then
        echo -e "  ${CYAN}/etc/crontab:${NC}"
        grep -vE '^[[:space:]]*(#|$)|^[A-Z_]+=' /etc/crontab | sed 's/^/    /'
    fi
    local cfile
    while read -r cfile; do
        hits=$(grep -E "$suspicious_re" "$cfile" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n 5)
        [[ -n "$hits" ]] || continue
        if [[ -n "$(pkg_owner "$cfile")" ]]; then
            package_owned+=("${cfile}: ${hits}")
        else
            foreign+=("${cfile}: ${hits}")
        fi
    done < <(find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -type f 2>/dev/null; [[ -f /etc/crontab ]] && echo /etc/crontab)

    subsection "Systemd Timers"
    local timer unit exec_path from_tmp=() writable=()
    if have systemctl; then
        systemctl list-timers --no-pager --no-legend 2>/dev/null | awk '{print $(NF-1), "->", $NF}' | head -n 15 | sed 's/^/  /'
        # The command a timer runs lives in the unit it activates
        while read -r timer; do
            unit=$(systemctl show -P Unit "$timer" 2>/dev/null)
            [[ -n "$unit" ]] || continue
            while read -r exec_path; do
                if [[ "$exec_path" =~ ^(/tmp|/dev/shm|/var/tmp)/ ]]; then
                    from_tmp+=("${timer}: ${exec_path}")
                elif [[ -f "$exec_path" ]] && mode_has "$(file_mode "$exec_path")" 022; then
                    writable+=("${timer}: ${exec_path} (mode $(file_mode "$exec_path"))")
                fi
            done < <(systemctl show -P ExecStart "$unit" 2>/dev/null | grep -oE 'path=[^ ;]+' | cut -d= -f2)
        done < <(systemctl list-units --type=timer --all --no-legend --plain 2>/dev/null | awk '{print $1}')
    fi

    if have atq; then
        local at_jobs
        at_jobs=$(atq 2>/dev/null)
        [[ -n "$at_jobs" ]] && log_info "Pending 'at' jobs:" "$at_jobs"
    fi

    [[ ${#foreign[@]} -gt 0 ]] && log_crit "Cron jobs with download/decode/reverse-shell patterns:" "${foreign[@]}"
    [[ ${#package_owned[@]} -gt 0 ]] && log_warn "Package-owned cron files match a suspicious pattern (verify with debsums -c):" "${package_owned[@]}"
    [[ ${#from_tmp[@]} -gt 0 ]] && log_crit "systemd timers execute programs from temporary directories:" "${from_tmp[@]}"
    [[ ${#writable[@]} -gt 0 ]] && log_warn "systemd timers execute group/world-writable programs:" "${writable[@]}"
    if [[ ${#foreign[@]} -eq 0 && ${#package_owned[@]} -eq 0 && ${#from_tmp[@]} -eq 0 && ${#writable[@]} -eq 0 ]]; then
        log_pass "No suspicious cron jobs or systemd timers."
    fi
}

register_section persistence "Persistence: Cron Jobs, Systemd Timers & at Jobs" section_persistence
