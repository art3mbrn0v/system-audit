# Logging and auditing services.

section_logging() {
    subsection "System Logging (journald / rsyslog)"
    local working=false
    if unit_active rsyslog; then
        working=true
        log_pass "rsyslog is active."
    elif unit_exists rsyslog.service; then
        log_warn "rsyslog is installed but not running."
    fi
    if unit_active systemd-journald; then
        working=true
        log_pass "systemd-journald is active."
    fi

    # Are logs actually being written?
    local auth_log="" age_h
    [[ -f /var/log/auth.log ]] && auth_log=/var/log/auth.log
    [[ -f /var/log/secure ]] && auth_log=/var/log/secure
    if [[ -n "$auth_log" ]]; then
        age_h=$(( ($(date +%s) - $(stat -c %Y "$auth_log" 2>/dev/null || echo 0)) / 3600 ))
        if [[ "$age_h" -le 24 ]]; then
            working=true
        else
            log_warn "${auth_log} has not been written for ${age_h}h: authentication logging may be broken."
        fi
    elif have journalctl; then
        if [[ -n "$(journalctl --since "24 hours ago" -n 1 --no-pager 2>/dev/null)" ]]; then
            working=true
        else
            log_warn "The journal has no entries for the last 24 hours: system activity is not recorded."
        fi
    fi
    [[ "$working" == false ]] && log_crit "No working system logging found (neither journald nor rsyslog): security events are not recorded."

    subsection "Kernel Audit Framework (auditd)"
    if unit_active auditd; then
        log_pass "auditd is active (kernel audit events are recorded; $(wc -l 2>/dev/null < /var/log/audit/audit.log || echo 0) entries in audit.log)."
    elif unit_exists auditd.service; then
        log_warn "auditd is installed but not running: security-relevant kernel events are not audited."
        [[ "$AUTO_RESTART_SERVICES" == true ]] && restart_service "auditd" "enabling kernel security auditing"
    else
        log_info "auditd is not installed (optional: apt install auditd / dnf install audit)."
    fi
}

register_section logging "Logging & Auditing Services (journald / rsyslog / auditd)" section_logging
