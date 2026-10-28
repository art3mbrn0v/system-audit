# Disk encryption and mandatory access control.

audit_disk_encryption() {
    subsection "Full Disk Encryption (LUKS)"
    local luks_devices=0 dev
    if have lsblk; then
        lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null | sed 's/^/  /'
        luks_devices=$(lsblk -rno FSTYPE 2>/dev/null | grep -cx 'crypto_LUKS')
    fi
    if have cryptsetup && [[ "$luks_devices" -eq 0 ]]; then
        while read -r dev; do
            cryptsetup isLuks "$dev" 2>/dev/null && luks_devices=$((luks_devices + 1))
        done < <(lsblk -rno PATH,TYPE 2>/dev/null | awk '$2 == "part" || $2 == "disk" {print $1}')
    fi

    # LUKS is identified via the device stack; /dev/mapper alone could be plain LVM
    if root_on_luks; then
        log_pass "Root filesystem is on a LUKS-encrypted device (${luks_devices} LUKS device(s) in total)."
    elif [[ "$luks_devices" -gt 0 ]]; then
        log_warn "LUKS is used (${luks_devices} device(s)), but the root filesystem is NOT encrypted."
    else
        log_crit "No disk encryption: a stolen disk exposes all data. Recommended: LUKS full disk encryption."
    fi

    if awk '!/^[[:space:]]*#/ && NF >= 3 && $3 ~ /^\// {found = 1} END {exit !found}' /etc/crypttab 2>/dev/null; then
        log_warn "crypttab unlocks a volume with a key file on disk (no passphrase prompt):" \
            "$(awk '!/^[[:space:]]*#/ && NF >= 3 && $3 ~ /^\// {print $1 " -> " $3}' /etc/crypttab)"
    fi
}

audit_mac() {
    subsection "Mandatory Access Control (SELinux / AppArmor)"
    local active=false
    if have getenforce; then
        case "$(getenforce 2>/dev/null)" in
            Enforcing)  log_pass "SELinux is enforcing."; active=true ;;
            Permissive) log_warn "SELinux is permissive: violations are logged but not blocked." ;;
            Disabled)   log_warn "SELinux is disabled." ;;
        esac
    fi

    local profiles
    profiles=$(wc -l 2>/dev/null < /sys/kernel/security/apparmor/profiles || echo 0)
    if have aa-enabled; then
        aa-enabled &>/dev/null
        case $? in
            0) log_pass "AppArmor is enabled with ${profiles} loaded profile(s)."; active=true ;;
            2) log_warn "AppArmor is enabled but no profiles are loaded." ;;
            *) log_warn "AppArmor is installed but disabled." ;;
        esac
    elif [[ -d /sys/kernel/security/apparmor ]]; then
        active=true
        log_pass "AppArmor is active with ${profiles} loaded profile(s)."
    fi
    [[ "$active" == false ]] && log_crit "No mandatory access control (SELinux/AppArmor) is active: a compromised service gets everything its user can reach."
}

section_encryption_and_mac() {
    audit_disk_encryption
    audit_mac
}

register_section crypto "Disk Encryption (LUKS) & MAC Framework (SELinux / AppArmor)" section_encryption_and_mac
