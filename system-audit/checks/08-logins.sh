# Logins, sessions, boots and authentication logs.

LAST_OUTPUT=""
LAST_LOADED=false
# Login history from wtmp/wtmpdb, read once: `last -w` (full user names), without the trailer line
wtmp_log() {
    if [[ "$LAST_LOADED" != true ]]; then
        LAST_LOADED=true
        have last && LAST_OUTPUT=$(last -w 2>/dev/null | grep -vE '^$|^wtmp(db)? begins')
    fi
    [[ -n "$LAST_OUTPUT" ]] && printf '%s\n' "$LAST_OUTPUT"
}

audit_sessions() {
    subsection "Active Sessions & Recent Logins"
    if have who; then
        local sessions
        sessions=$(who 2>/dev/null)
        if [[ -n "$sessions" ]]; then
            who -H 2>/dev/null
            matches '^root[[:space:]]' "$sessions" && log_warn "Root account has an active interactive login session."
        else
            echo "No active interactive login sessions."
        fi
    fi

    step "Recent logins (last 10 records):"
    local recent remote
    recent=$(wtmp_log | head -n 10)
    echo "${recent:-No login records available.}"
    remote=$(grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$recent")
    [[ -n "$remote" ]] && log_info "Logins from remote IP addresses:" "$remote"
}

audit_unclean_shutdowns() {
    have journalctl || return 0
    # 'crash' in last is unreliable (GNOME leaves wtmp records open on clean reboots),
    # so judge each previous boot by whether its journal reached the systemd shutdown
    local offsets off tail_lines unclean=()
    offsets=$(journalctl --list-boots --no-pager 2>/dev/null | awk '$1 ~ /^-[0-9]+$/ {print $1}' | tail -n 10)
    for off in $offsets; do
        tail_lines=$(journalctl -b "$off" -n 40 -q --no-pager 2>/dev/null)
        [[ -n "$tail_lines" ]] || continue
        matches 'systemd-shutdown|Journal stopped|Reached target .*(Power-Off|Reboot|Halt|Shutdown)' "$tail_lines" && continue
        unclean+=("boot ${off}: last entry $(tail -n 1 <<< "$tail_lines" | cut -c1-15)")
    done
    if [[ ${#unclean[@]} -gt 0 ]]; then
        log_warn "Previous boot(s) ended without a clean shutdown (freeze / power loss / kernel panic; inspect with journalctl -b <offset> -e):" "${unclean[@]}"
    elif [[ -n "$offsets" ]]; then
        log_pass "Last $(wc -w <<< "$offsets") boot(s) ended with a clean shutdown/reboot."
    fi
}

audit_account_activity() {
    subsection "Login Activity of Interactive Accounts"
    if have lastb; then
        local failed failed_n
        failed=$(lastb -s -24hours 2>/dev/null | grep -vE '^$|btmp begins')
        failed_n=$(count_lines "$failed")
        if [[ "$failed_n" -gt 50 ]]; then
            log_crit "${failed_n} failed logins in the last 24h (btmp) - potential brute-force attack." "$(head -n 10 <<< "$failed")"
        elif [[ "$failed_n" -gt 0 ]]; then
            log_warn "${failed_n} failed login(s) in the last 24h (btmp):" "$(head -n 10 <<< "$failed")"
        else
            log_pass "No failed logins in the last 24h (btmp)."
        fi
    else
        echo -e "${DIM}lastb is not installed - failed logins are evaluated from the journal below.${NC}"
    fi

    local user uid home shell entry never=()
    while IFS=: read -r user uid home shell; do
        has_login_shell "$shell" || continue
        if have lastlog; then
            entry=$(lastlog -u "$user" 2>/dev/null | tail -n 1)
        elif have lastlog2; then
            entry=$(lastlog2 --user "$user" 2>/dev/null | tail -n 1)
        else
            entry=$(wtmp_log | awk -v u="$user" '$1 == u {print; exit}')
            [[ -z "$entry" ]] && entry="**Never logged in**"
        fi
        if [[ "$entry" == *"Never logged in"* ]]; then
            [[ "$uid" -ge 1000 ]] && never+=("${user} (UID ${uid})")
            echo -e "  - ${CYAN}${user}${NC}: never logged in"
        else
            echo -e "  - ${CYAN}${user}${NC}: ${entry}"
        fi
    done < <(all_accounts)
    [[ ${#never[@]} -gt 0 ]] && log_warn "Interactive user accounts that never logged in (unused accounts are attack surface):" "${never[@]}"
}

audit_auth_logs() {
    subsection "Authentication Failures & Crashes in the Logs (last 24h)"
    local auth_re='authentication failure|Failed password|Invalid user|FAILED LOGIN|NOT in sudoers|maximum authentication attempts|incorrect password attempts|Failed publickey'
    local remote_re='Failed password|Invalid user|Failed publickey|maximum authentication attempts'
    local crash_re='segfault|Out of memory: Kill process|general protection fault|kernel BUG|Oops:'

    if have journalctl; then
        local auth_lines auth_count remote_count top crash_lines denied
        auth_lines=$(journalctl --since "24 hours ago" --no-pager -o cat -g "$auth_re" 2>/dev/null | sed '/^$/d')
        auth_count=$(count_lines "$auth_lines")
        remote_count=$(grep -cE "$remote_re" <<< "$auth_lines")
        top=$(sed -E 's/[0-9]+/N/g' <<< "$auth_lines" | cut -c1-110 | sort | uniq -c | sort -rn | head -n 5)
        echo -e "Authentication failures (24h): ${CYAN}${auth_count}${NC} (remote/ssh-style: ${CYAN}${remote_count}${NC})"

        if [[ "$remote_count" -gt 20 ]]; then
            log_crit "${remote_count} remote-style authentication failures in 24h - possible brute-force attack." "$top"
        elif [[ "$auth_count" -gt 20 ]]; then
            log_warn "${auth_count} local authentication failures in 24h (mistyped sudo/unlock passwords or a misbehaving service)." "$top"
        elif [[ "$auth_count" -gt 0 ]]; then
            log_pass "Only ${auth_count} local authentication failure(s) in 24h; no brute-force pattern." "$top"
        else
            log_pass "No authentication failures in the journal (last 24h)."
        fi

        crash_lines=$(journalctl --since "24 hours ago" --no-pager -o short-iso -p warning..emerg -g "$crash_re" 2>/dev/null | grep -v '^-- ' | tail -n 10)
        if [[ -n "$crash_lines" ]]; then
            log_warn "Crash / OOM / kernel-fault entries in the journal (last 24h):" "$crash_lines"
        else
            log_pass "No crash, OOM or kernel-fault entries in the journal (last 24h)."
        fi

        denied=$(journalctl -k --since "24 hours ago" --no-pager -o cat -g 'apparmor="DENIED"' 2>/dev/null | grep -c .)
        [[ "$denied" -gt 0 ]] && log_info "AppArmor logged ${denied} DENIED event(s) in 24h (review: journalctl -k -g 'apparmor=\"DENIED\"')."
    fi

    local logfile hits
    for logfile in /var/log/auth.log /var/log/secure; do
        [[ -f "$logfile" ]] || continue
        hits=$(grep -E "$auth_re" "$logfile" 2>/dev/null | tail -n 10)
        if [[ -n "$hits" ]]; then
            log_warn "Recent authentication failures in ${logfile}:" "$hits"
        else
            log_pass "No authentication failures in ${logfile}."
        fi
    done

    step "Recent sudo usage:"
    local sudo_lines=""
    if [[ -f /var/log/secure ]]; then
        sudo_lines=$(grep "sudo" /var/log/secure 2>/dev/null | tail -n 10)
    elif [[ -f /var/log/auth.log ]]; then
        sudo_lines=$(grep "sudo" /var/log/auth.log 2>/dev/null | tail -n 10)
    elif have journalctl; then
        sudo_lines=$(journalctl _COMM=sudo -n 10 --no-pager 2>/dev/null)
    fi
    echo "${sudo_lines:-No sudo records found.}"
}

section_logins() {
    audit_sessions
    audit_unclean_shutdowns
    audit_account_activity
    audit_auth_logs
}

register_section logins "User Logins, Sessions, Boots & Authentication Logs" section_logins
