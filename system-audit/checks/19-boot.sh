# Bootloader, Secure Boot, kernel command line and sysctl hardening.

# grub_setting KEY: value of KEY in /etc/default/grub, quotes removed
grub_setting() { grep -m1 "^$1=" /etc/default/grub 2>/dev/null | cut -d= -f2- | tr -d "\"'"; }

audit_grub() {
    subsection "GRUB Configuration, Password & Recovery Mode"
    local cfg found_cfg="" owner mode
    for cfg in /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/efi/EFI/{debian,ubuntu,redhat,centos,fedora}/grub.cfg; do
        [[ -f "$cfg" ]] && { found_cfg="$cfg"; break; }
    done
    if [[ -z "$found_cfg" ]]; then
        echo "  No GRUB configuration found (systemd-boot / EFI stub?)."
        return 0
    fi
    owner=$(stat -c "%U:%G" "$found_cfg" 2>/dev/null)
    mode=$(file_mode "$found_cfg")
    echo -e "  ${found_cfg}: mode ${mode}, owner ${owner}"
    if [[ "$mode" =~ ^(600|700|400|440)$ && "$owner" == root:* ]]; then
        log_pass "GRUB configuration is root-only (${mode})."
    else
        log_warn "GRUB configuration ${found_cfg} is readable by others or not owned by root (${mode} ${owner}); recommended 600 root:root."
    fi

    if grep -qsE "password_pbkdf2|password " "$found_cfg" || grep -rqsE "password_pbkdf2|password " /etc/grub.d/; then
        log_pass "GRUB menu is password protected."
    elif root_on_luks; then
        log_info "GRUB is not password protected, but / is on LUKS: an edited cmdline (init=/bin/bash) still needs the disk passphrase. Remaining risk: tampering with unencrypted /boot (mitigated by Secure Boot)."
    else
        log_warn "GRUB is not password protected and / is not encrypted: console access allows booting into a root shell."
    fi

    local disable_rec root_pw timeout
    disable_rec=$(grub_setting GRUB_DISABLE_RECOVERY)
    if [[ "$disable_rec" == "true" || "$disable_rec" == "1" ]]; then
        log_pass "GRUB recovery mode entries are disabled."
    else
        root_pw=$(passwd -S root 2>/dev/null | awk '{print $2}')
        if [[ "$root_pw" == "P" ]]; then
            log_info "GRUB recovery mode is enabled, but root has a password: recovery mode asks for it (sulogin)."
        else
            log_warn "GRUB recovery mode is enabled and root has no usable password (${root_pw:-unknown}): recovery mode may open a root shell without authentication."
        fi
    fi

    timeout=$(grub_setting GRUB_TIMEOUT)
    if [[ "$timeout" =~ ^-?[0-9]+$ ]] && [[ "$timeout" -eq -1 || "$timeout" -gt 10 ]]; then
        log_warn "GRUB_TIMEOUT=${timeout}: a long boot menu delay widens the tampering window (recommended <= 5)."
    fi
}

audit_boot_state() {
    subsection "Kernel Command Line & Secure Boot"
    local cmdline tok tokens dangerous=() weakened=()
    cmdline=$(cat /proc/cmdline 2>/dev/null)
    echo -e "  /proc/cmdline: ${CYAN}${cmdline}${NC}"
    read -ra tokens <<< "$cmdline"
    for tok in "${tokens[@]}"; do
        case "$tok" in
            init=/bin/bash|init=/bin/sh|rd.break|rd.break=*|emergency|systemd.unit=emergency.target|single|s|S|1|systemd.unit=rescue.target)
                dangerous+=("$tok") ;;
            selinux=0|enforcing=0|apparmor=0|mitigations=off|noibrs|noibpb|nopti|nospectre_v1|nospectre_v2|nospec_store_bypass_disable)
                weakened+=("$tok") ;;
        esac
    done
    [[ ${#dangerous[@]} -gt 0 ]] && log_crit "Kernel booted with a root-shell / single-user parameter:" "${dangerous[@]}"
    if [[ ${#weakened[@]} -gt 0 ]]; then
        log_warn "Kernel booted with security features disabled (MAC or CPU vulnerability mitigations):" "${weakened[@]}"
    else
        log_pass "No security features disabled on the kernel command line."
    fi

    if have mokutil; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null)
        if [[ "$sb_state" == *"SecureBoot enabled"* ]]; then
            log_pass "UEFI Secure Boot is enabled."
        else
            log_warn "UEFI Secure Boot is disabled (${sb_state:-state unknown}): boot chain tampering is not detected."
        fi
    elif [[ -d /sys/firmware/efi ]]; then
        local sb_var
        sb_var=$(find /sys/firmware/efi/efivars/ -name "SecureBoot-*" 2>/dev/null | head -n 1)
        if [[ -n "$sb_var" && "$(od -An -t u1 "$sb_var" 2>/dev/null | awk '{print $NF}')" == "1" ]]; then
            log_pass "UEFI Secure Boot is enabled (efivars)."
        elif [[ -n "$sb_var" ]]; then
            log_warn "UEFI Secure Boot is disabled (efivars)."
        fi
    else
        echo "  Legacy BIOS boot (Secure Boot not applicable)."
    fi
}

# "parameter|recommended|explanation"; a recommended value ">=N" accepts N and more
SYSCTL_EXPECTED=(
    "kernel.kptr_restrict|>=1|hides kernel addresses from unprivileged users"
    "kernel.dmesg_restrict|1|kernel log readable by root only"
    "kernel.yama.ptrace_scope|>=1|processes cannot read the memory of other processes of the same user"
    "kernel.randomize_va_space|2|full ASLR"
    "fs.protected_symlinks|1|symlink attacks in sticky directories blocked"
    "fs.protected_hardlinks|1|hardlink attacks blocked"
    "fs.suid_dumpable|0|SUID programs do not write core dumps"
    "net.ipv4.tcp_syncookies|1|SYN flood protection"
    "net.ipv4.ip_forward|0|host does not route packets"
    "net.ipv6.conf.all.forwarding|0|host does not route IPv6 packets"
)

audit_sysctl() {
    subsection "Kernel Hardening Parameters (sysctl)"
    local entry param want why value bad=() bridges=false
    matches ': (virbr|docker)[0-9]' "$(ip -o link show 2>/dev/null)" && bridges=true
    for entry in "${SYSCTL_EXPECTED[@]}"; do
        IFS='|' read -r param want why <<< "$entry"
        value=$(sysctl -n "$param" 2>/dev/null)
        [[ -n "$value" ]] || continue
        echo "  ${param} = ${value}"
        if [[ "$param" == *forward* && "$value" != "0" && "$bridges" == true ]]; then
            continue   # libvirt/docker NAT networking needs forwarding
        fi
        if [[ "$want" == ">="* ]]; then
            [[ "$value" -ge "${want#>=}" ]] && continue
        else
            [[ "$value" == "$want" ]] && continue
        fi
        bad+=("${param} = ${value} (recommended ${want#>=}: ${why})")
    done
    [[ "$bridges" == true ]] && echo -e "  ${DIM}IP forwarding is allowed: libvirt/docker bridges need it.${NC}"
    if [[ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" == "0" ]]; then
        log_crit "ASLR is disabled (kernel.randomize_va_space = 0): memory-corruption exploits become reliable."
    fi
    if [[ ${#bad[@]} -gt 0 ]]; then
        log_warn "Kernel hardening parameters below the recommended value (set them in /etc/sysctl.d/):" "${bad[@]}"
    else
        log_pass "All checked kernel hardening parameters have the recommended values."
    fi

    local core_pattern
    core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
    if [[ "$core_pattern" =~ ^(/tmp/|/var/tmp/|/dev/shm/) ]]; then
        log_crit "Core dumps are written to a world-writable directory (process memory exposed): ${core_pattern}"
    fi
}

section_boot_and_kernel() {
    audit_grub
    audit_boot_state
    audit_sysctl
}

register_section boot "Bootloader, Secure Boot & Kernel Hardening (sysctl)" section_boot_and_kernel
