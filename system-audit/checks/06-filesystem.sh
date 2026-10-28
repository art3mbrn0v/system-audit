# Filesystem permissions, integrity and temporary directories.

# Expected permissions: "path:allowed-mode-regex:owner"
CRITICAL_FILES=(
    "/etc/passwd:^644$:root"
    "/etc/group:^644$:root"
    "/etc/shadow:^(600|640)$:root"
    "/etc/gshadow:^(600|640)$:root"
    "/etc/sudoers:^(440|400)$:root"
    "/etc/fstab:^644$:root"
    "/etc/crontab:^(600|644)$:root"
    "/boot/grub/grub.cfg:^(600|700)$:root"
    "/boot/grub2/grub.cfg:^(600|700)$:root"
    "/etc/sysctl.conf:^644$:root"
    "/etc/ssh/sshd_config:^(600|644)$:root"
)
CRITICAL_DIRS=(
    "/etc:^755$:root"
    "/etc/sudoers.d:^(750|755)$:root"
    "/etc/cron.d:^(755|700)$:root"
    "/etc/cron.daily:^(755|700)$:root"
    "/etc/cron.hourly:^(755|700)$:root"
    "/etc/cron.weekly:^(755|700)$:root"
    "/etc/cron.monthly:^(755|700)$:root"
    "/etc/pam.d:^755$:root"
    "/bin:^755$:root"
    "/sbin:^755$:root"
    "/usr/bin:^755$:root"
    "/usr/sbin:^755$:root"
    "/lib:^755$:root"
    "/lib64:^755$:root"
    "/var/log:^(755|775)$:root"
)

audit_permissions_matrix() {
    subsection "Critical System Files & Directories: Permissions and Ownership"
    local item path mode_re owner_want mode owner checked=0 bad_mode=() bad_owner=()
    for item in "${CRITICAL_FILES[@]}" "${CRITICAL_DIRS[@]}"; do
        IFS=":" read -r path mode_re owner_want <<< "$item"
        [[ -e "$path" ]] || continue
        checked=$((checked + 1))
        mode=$(file_mode "$path")
        owner=$(stat -L -c %U "$path" 2>/dev/null)
        [[ "$mode" =~ $mode_re ]] || bad_mode+=("${path}: mode ${mode} (expected ${mode_re//[\^\$()]/})")
        [[ -n "$owner" && "$owner" != "$owner_want" ]] && bad_owner+=("${path}: owner ${owner} (expected ${owner_want})")
    done
    [[ ${#bad_owner[@]} -gt 0 ]] && log_crit "Critical system files/directories NOT owned by root:" "${bad_owner[@]}"
    [[ ${#bad_mode[@]} -gt 0 ]] && log_warn "Critical system files/directories with non-standard permissions:" "${bad_mode[@]}"
    if [[ ${#bad_owner[@]} -eq 0 && ${#bad_mode[@]} -eq 0 ]]; then
        log_pass "All ${checked} critical system files and directories have the expected permissions and root ownership."
    fi

    local hk mode_hk host_keys=0 bad_keys=()
    while read -r hk; do
        host_keys=$((host_keys + 1))
        mode_hk=$(file_mode "$hk")
        [[ "$mode_hk" =~ ^(600|640)$ ]] || bad_keys+=("${hk} (mode ${mode_hk})")
    done < <(find /etc/ssh -maxdepth 1 -type f -name "ssh_host_*_key" 2>/dev/null)
    if [[ ${#bad_keys[@]} -gt 0 ]]; then
        log_crit "SSH private host keys readable by others (must be 600 or 640):" "${bad_keys[@]}"
    elif [[ "$host_keys" -gt 0 ]]; then
        log_pass "SSH private host keys (${host_keys}) are protected (600/640)."
    fi
}

audit_temp_and_home_dirs() {
    subsection "Shared Temporary Directories & Sensitive Dot-Folders"
    local tdir no_sticky=()
    for tdir in /tmp /var/tmp /dev/shm; do
        [[ -d "$tdir" && ! -k "$tdir" ]] && no_sticky+=("${tdir} (mode $(file_mode "$tdir"))")
    done
    if [[ ${#no_sticky[@]} -gt 0 ]]; then
        log_crit "Shared temporary directories WITHOUT sticky bit (users can delete each other's files):" "${no_sticky[@]}"
    else
        log_pass "Sticky bit set on /tmp, /var/tmp and /dev/shm."
    fi

    local user uid home shell dot dot_path mode loose=()
    while IFS=: read -r user uid home shell; do
        for dot in .ssh .gnupg .aws .kube .docker .config/gcloud; do
            dot_path="$home/$dot"
            [[ -d "$dot_path" ]] || continue
            mode=$(file_mode "$dot_path")
            mode_has "$mode" 077 && loose+=("${dot_path} (mode ${mode}, $(stat -c %U:%G "$dot_path" 2>/dev/null))")
        done
    done < <(human_accounts)
    if [[ ${#loose[@]} -gt 0 ]]; then
        log_warn "Sensitive dot-folders accessible to group/others (recommended: chmod 700):" "${loose[@]}"
    else
        log_pass "Sensitive dot-folders (.ssh, .gnupg, .aws, .kube, .docker, gcloud) are private."
    fi
}

audit_world_writable_dirs() {
    subsection "World-Writable Directories Without Sticky Bit"
    local roots dirs no_sticky sticky_count private_count
    mapfile -t roots < <(local_fs_roots)
    dirs=$( { scan_find "${roots[@]}" -- -type d -perm -0002
              find /dev/shm -maxdepth 1 -type d -perm -0002 2>/dev/null; } | sort -u)
    private_count=$(grep -c '/systemd-private-' <<< "$dirs")
    dirs=$(grep -v '/systemd-private-' <<< "$dirs" | sed '/^$/d')

    no_sticky=$(while read -r d; do [[ -n "$d" && ! -k "$d" ]] && echo "$d (mode $(file_mode "$d"))"; done <<< "$dirs")
    sticky_count=$(( $(count_lines "$dirs") - $(count_lines "$no_sticky") ))
    echo "  World-writable directories with sticky bit: ${sticky_count} (+ ${private_count} systemd PrivateTmp)"
    if [[ -n "$no_sticky" ]]; then
        log_crit "World-writable directories WITHOUT sticky bit (any user can delete or replace others' files):" "$no_sticky"
    else
        log_pass "All world-writable directories on local filesystems have the sticky bit."
    fi
}

audit_package_integrity() {
    subsection "System Binary Integrity (debsums / rpm -V)"
    slow_scan "Package checksum verification" || return 0
    if have debsums; then
        echo "Running debsums integrity verification on system packages..."
        # stdout = files whose checksum really differs; stderr = "missing file" notes.
        # Missing files (e.g. docker-desktop's /DEBIAN/*, Papirus icons) are NOT modifications.
        local changed missing core other
        local core_re='^/(usr/)?(bin|sbin|lib|lib64|libexec)/|^/usr/lib/|^/boot/'
        changed=$(debsums -c 2>"$WORK_DIR/debsums.err")
        missing=$(grep -c 'missing file' "$WORK_DIR/debsums.err" 2>/dev/null)
        core=$(grep -E "$core_re" <<< "$changed")
        other=$(grep -vE "$core_re" <<< "$changed" | sed '/^$/d')
        [[ -n "$core" ]] && log_crit "System binaries/libraries differ from their package checksums (possible tampering):" "$core"
        [[ -n "$other" ]] && log_warn "Package files modified locally (not core binaries):" "$other"
        [[ -z "$changed" ]] && log_pass "debsums: no package file differs from its checksum."
        [[ "${missing:-0}" -gt 0 ]] && log_info "debsums: ${missing} package file(s) are missing on disk (not tampering; usually removed icons or packaging quirks)."
    elif have rpm; then
        local rpm_out
        rpm_out=$(rpm -Vf /bin/ls /bin/login /usr/sbin/sshd 2>/dev/null | grep -E '^..5')
        if [[ -n "$rpm_out" ]]; then
            log_crit "Core system binaries differ from their RPM checksums:" "$rpm_out"
        else
            log_pass "RPM core binary checksums verified."
        fi
    else
        echo -e "${YELLOW}debsums/rpm not available for binary checksum verification.${NC}"
    fi
}

audit_rotated_logs() {
    subsection "Rotated Logs (/var/log)"
    local listing count total_bytes
    # "size path" of rotated/compressed archives
    listing=$(find /var/log -type f \( -name "*.gz" -o -name "*.1" -o -name "*.old" \) -size +0 -printf '%s %p\n' 2>/dev/null)
    if [[ -z "$listing" ]]; then
        echo "No rotated log archives in /var/log."
        return 0
    fi
    count=$(count_lines "$listing")
    total_bytes=$(awk '{s += $1} END {print s + 0}' <<< "$listing")
    echo -e "  ${count} rotated/compressed log file(s) occupy ${CYAN}$(human_size "$total_bytes")${NC}."
    if [[ "$CLEAN_CACHE" == true ]]; then
        # Only archives older than 14 days: recent logs stay available for incident investigation
        local old_bytes
        old_bytes=$(find /var/log -type f \( -name "*.gz" -o -name "*.1" -o -name "*.old" \) -mtime +14 -printf '%s\n' -delete 2>/dev/null | awk '{s += $1} END {print s + 0}')
        echo -e "  ${GREEN}Removed archives older than 14 days: $(human_size "$old_bytes") reclaimed.${NC}"
    fi
}

audit_luks_keyfiles_in_tmp() {
    subsection "LUKS Keyfiles in Temporary Directories (/tmp, /var/tmp, /dev/shm)"
    local found=() target dev key_path kfile mode cand

    # crypttab entries whose keyfile lives in a temporary directory
    if [[ -f /etc/crypttab ]]; then
        while read -r target dev key_path _; do
            [[ -z "$target" || "$target" == \#* ]] && continue
            [[ "$key_path" =~ ^(/tmp/|/var/tmp/|/dev/shm/) ]] && found+=("crypttab: ${target} uses keyfile ${key_path}")
        done < /etc/crypttab
    fi
    # Files named like LUKS/encryption keys
    while read -r kfile; do
        mode=$(file_mode "$kfile")
        found+=("${kfile} (mode ${mode}, $(stat -c %U:%G "$kfile" 2>/dev/null))")
        if [[ "$AUTO_FIX" == true ]] && mode_has "$mode" 077; then
            chmod 600 "$kfile" 2>/dev/null && echo -e "  ${GREEN}Auto-fix: ${kfile} set to 600.${NC}"
        fi
    done < <(find /tmp /var/tmp /dev/shm -maxdepth 3 -type f \( -iname "*luks*" -o -iname "*keyfile*" -o -iname "*crypt*key*" -o -iname "*volume.key" \) 2>/dev/null)
    # Binary LUKS headers / containers
    if have cryptsetup; then
        while read -r cand; do
            cryptsetup isLuks "$cand" 2>/dev/null && found+=("${cand} (LUKS header/container)")
        done < <(find /tmp /var/tmp /dev/shm -maxdepth 2 -type f \( -name "*.img" -o -name "*.raw" -o -name "*.luks" -o -name "*.key" \) 2>/dev/null)
    fi

    if [[ ${#found[@]} -gt 0 ]]; then
        log_crit "LUKS keys or containers in temporary directories:" "${found[@]}"
    else
        log_pass "No LUKS keyfiles, containers or crypttab key references in temporary directories."
    fi
}

audit_orphaned_files() {
    subsection "Files Without Owner or Group (-nouser / -nogroup)"
    local orphans
    orphans=$(scan_find /etc /var /opt /home /tmp /usr /srv /boot -maxdepth 4 -- \( -nouser -o -nogroup \))
    if [[ -n "$orphans" ]]; then
        log_warn "Files/directories whose owner or group no longer exists ($(count_lines "$orphans")):" "$orphans"
    else
        log_pass "No files without a valid owner or group."
    fi
}

section_filesystem() {
    audit_permissions_matrix
    audit_temp_and_home_dirs
    audit_world_writable_dirs
    audit_package_integrity
    audit_rotated_logs
    audit_luks_keyfiles_in_tmp
    audit_orphaned_files
}

register_section files "Filesystem Permissions, Integrity & Temporary Directories" section_filesystem
