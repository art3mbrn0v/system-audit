# System resources and housekeeping.

audit_time_sync() {
    subsection "Timezone & Time Synchronization"
    local tz_abbr tz_name synced=false
    tz_abbr=$(date "+%Z")
    if [[ -L /etc/localtime ]]; then
        tz_name=$(readlink -f /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||')
    elif [[ -f /etc/timezone ]]; then
        tz_name=$(cat /etc/timezone 2>/dev/null)
    fi
    tz_name=${tz_name:-$tz_abbr}
    echo -e "  Timezone: ${CYAN}${tz_name}${NC} (${tz_abbr}, UTC$(date "+%z"))"

    if have timedatectl; then
        local status ntp_sync ntp_service
        status=$(timedatectl status 2>/dev/null)
        ntp_sync=$(awk -F': ' '/System clock synchronized:/ {print $2}' <<< "$status")
        ntp_service=$(awk -F': ' '/NTP service:/ {print $2}' <<< "$status")
        echo -e "  NTP service: ${CYAN}${ntp_service:-unknown}${NC}, clock synchronized: ${CYAN}${ntp_sync:-unknown}${NC}"
        [[ "$ntp_sync" == "yes" ]] && synced=true
    elif unit_active systemd-timesyncd || unit_active chronyd || unit_active ntp; then
        synced=true
    fi
    if [[ "$synced" == true ]]; then
        log_pass "System clock is synchronized via NTP."
    else
        log_warn "System clock is NOT synchronized with NTP (log timestamps and TLS validation may be wrong)."
    fi
}

audit_disk_usage() {
    subsection "Disk Space"
    local df_out alerts=() fs size avail pct mount
    df_out=$(df -h -x tmpfs -x devtmpfs -x squashfs -x efivarfs 2>/dev/null)
    echo "$df_out"
    while read -r fs size _ avail pct mount; do
        pct=${pct%\%}
        [[ "$pct" =~ ^[0-9]+$ && "$pct" -ge 80 ]] && alerts+=("${mount} (${fs}): ${pct}% used, ${avail} free of ${size}")
    done < <(tail -n +2 <<< "$df_out")
    if [[ ${#alerts[@]} -gt 0 ]]; then
        log_warn "Filesystems at least 80% full:" "${alerts[@]}"
    else
        log_pass "All filesystems have sufficient free space (< 80% used)."
    fi
}

audit_failed_units() {
    subsection "Failed systemd Units"
    have systemctl || return 0
    local failed unit
    failed=$(systemctl --failed --no-legend --plain 2>/dev/null)
    if [[ -z "$failed" ]]; then
        log_pass "No failed systemd units."
        return 0
    fi
    log_warn "Failed systemd units:" "$failed"
    if [[ "$AUTO_RESTART_SERVICES" == true ]]; then
        while read -r unit _; do
            [[ -n "$unit" ]] && restart_service "$unit" "recovering failed unit"
        done <<< "$failed"
    fi
}

audit_journal_and_packages() {
    subsection "Journal Size & Unused Packages"
    have journalctl && echo "  $(journalctl --disk-usage 2>/dev/null) (shrink: journalctl --vacuum-size=500M)"
    local unneeded=""
    case "$PKG_MGR" in
        apt) unneeded=$(apt-get autoremove --dry-run 2>/dev/null | awk '/^Remv / {print $2}') ;;
        dnf) unneeded=$(dnf autoremove --assumeno 2>/dev/null | awk '/^Removing/ {f = 1; next} f && NF {print $1}') ;;
    esac
    if [[ -n "$unneeded" ]]; then
        log_info "Packages no longer needed ($(count_lines "$unneeded")); remove with '${PKG_MGR} autoremove':" "$unneeded"
    elif [[ -n "$PKG_MGR" ]]; then
        echo "  No unused packages to autoremove."
    fi
}

audit_user_caches() {
    subsection "User Caches & Core Dumps (reclaimable space)"
    local cache_targets=(
        ".cache/thumbnails" ".local/share/Trash" ".cache/pip" ".cache/npm" ".cache/yarn"
        ".cache/pnpm" ".cache/go-build" ".cache/crash" ".local/share/crash"
        ".cache/Code/Cache" ".cache/Code/CachedData"
        ".cache/google-chrome/Default/Cache" ".cache/google-chrome/Profile */Cache"
        ".cache/chromium/Default/Cache" ".cache/mozilla/firefox/*/cache2"
    )
    local total_bytes=0 found=() user uid home shell rel target size_bytes core
    while IFS=: read -r user uid home shell; do
        [[ -d "$home" ]] || continue
        for rel in "${cache_targets[@]}"; do
            # Unquoted on purpose: the targets contain globs (Profile */, firefox/*/)
            for target in $home/$rel; do
                [[ -e "$target" ]] || continue
                size_bytes=$(du -sb "$target" 2>/dev/null | awk '{print $1}')
                [[ -n "$size_bytes" && "$size_bytes" -gt 1048576 ]] || continue
                total_bytes=$((total_bytes + size_bytes))
                found+=("${target} ($(human_size "$size_bytes"))")
                if [[ "$CLEAN_CACHE" == true ]]; then
                    if [[ -d "$target" ]]; then find "$target" -mindepth 1 -delete 2>/dev/null; else rm -f "$target"; fi
                fi
            done
        done
        while read -r core; do
            found+=("core dump ${core} ($(du -sh "$core" 2>/dev/null | awk '{print $1}'))")
            [[ "$CLEAN_CACHE" == true ]] && rm -f "$core"
        done < <(find "$home" -maxdepth 2 -type f \( -name "core" -o -regex '.*/core\.[0-9]+' \) 2>/dev/null)
    done < <(human_accounts)

    if [[ ${#found[@]} -eq 0 ]]; then
        echo "  No user caches larger than 1 MiB."
    elif [[ "$CLEAN_CACHE" == true ]]; then
        log_pass "Cleaned user caches: $(human_size "$total_bytes") reclaimed." "${found[@]}"
    else
        log_info "User caches take $(human_size "$total_bytes") (purge with --clean-cache):" "${found[@]}"
    fi
}

section_resources() {
    audit_time_sync
    audit_disk_usage
    audit_failed_units
    audit_journal_and_packages
    audit_user_caches
}

register_section resources "System Resources & Optimization Opportunities" section_resources
