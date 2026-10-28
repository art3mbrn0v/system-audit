# OpenSSH daemon configuration.

SSHD_EFFECTIVE=""   # `sshd -T` output (effective configuration), if available

# sshd_param NAME DEFAULT: effective value, else the first match in the config files
# (drop-ins first: Debian includes sshd_config.d/*.conf at the top and the first value wins)
sshd_param() {
    local name="$1" default="$2" val=""
    if [[ -n "$SSHD_EFFECTIVE" ]]; then
        val=$(awk -v p="$name" 'tolower($1) == p {print $2; exit}' <<< "$SSHD_EFFECTIVE")
    fi
    if [[ -z "$val" ]]; then
        val=$(cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \
              | awk -v p="$name" '!/^[[:space:]]*#/ && tolower($1) == p {print $2; exit}')
    fi
    echo "${val:-$default}"
}

audit_sshd_directives() {
    subsection "SSH Daemon Effective Configuration & Authentication Directives"
    local value

    value=$(sshd_param port 22)
    echo -e "  SSH Listening Port          : ${CYAN}${value}${NC}"
    if [[ "$value" == "22" ]]; then
        echo -e "  ${DIM}Tip: a non-standard port reduces automated brute-force noise in the logs.${NC}"
    else
        log_pass "SSH daemon running on custom non-standard port (${value})."
    fi

    value=$(sshd_param permitrootlogin prohibit-password)
    echo -e "  PermitRootLogin             : ${CYAN}${value}${NC}"
    case "$value" in
        yes) log_crit "PermitRootLogin is enabled ('yes'): direct root SSH login allows brute-force attacks against root. Recommended: 'no' or 'prohibit-password'." ;;
        prohibit-password|without-password) log_pass "PermitRootLogin set to '${value}' (root SSH login via key only)." ;;
        *) log_pass "PermitRootLogin set to '${value}' (direct root SSH login disabled)." ;;
    esac

    value=$(sshd_param passwordauthentication yes)
    echo -e "  PasswordAuthentication      : ${CYAN}${value}${NC}"
    if [[ "$value" == "yes" ]]; then
        log_warn "PasswordAuthentication is enabled: password brute-force is possible. Recommended: 'PasswordAuthentication no' with SSH keys."
    else
        log_pass "PasswordAuthentication is disabled (SSH key authentication enforced)."
    fi

    value=$(sshd_param permitemptypasswords no)
    echo -e "  PermitEmptyPasswords        : ${CYAN}${value}${NC}"
    if [[ "$value" == "yes" ]]; then
        log_crit "PermitEmptyPasswords is enabled: accounts with blank passwords can log in via SSH!"
    else
        log_pass "PermitEmptyPasswords is set to 'no'."
    fi

    value=$(sshd_param pubkeyauthentication yes)
    echo -e "  PubkeyAuthentication        : ${CYAN}${value}${NC}"
    if [[ "$value" == "no" ]]; then
        log_warn "PubkeyAuthentication is disabled: SSH key authentication is turned off."
    else
        log_pass "PubkeyAuthentication is enabled."
    fi

    value=$(sshd_param x11forwarding no)
    echo -e "  X11Forwarding               : ${CYAN}${value}${NC}"
    if [[ "$value" == "yes" ]]; then
        log_warn "X11Forwarding is enabled: X11 display redirection increases attack surface unless required."
    else
        log_pass "X11Forwarding is disabled."
    fi

    value=$(sshd_param maxauthtries 6)
    echo -e "  MaxAuthTries                : ${CYAN}${value}${NC}"
    if [[ "$value" =~ ^[0-9]+$ && "$value" -gt 4 ]]; then
        log_warn "MaxAuthTries is ${value} (recommended: <= 4 to slow down brute-force attempts)."
    else
        log_pass "MaxAuthTries configuration verified (${value})."
    fi
}

audit_sshd_crypto() {
    subsection "SSH Cryptographic Algorithms Audit (Ciphers, MACs, KEX)"
    local ciphers macs kex weak
    ciphers=$(sshd_param ciphers "")
    macs=$(sshd_param macs "")
    kex=$(sshd_param kexalgorithms "")

    if [[ -n "$ciphers" ]]; then
        echo -e "  Configured Ciphers          : ${CYAN}${ciphers}${NC}"
        weak=$(grep -oEi "3des-cbc|blowfish-cbc|cast128-cbc|aes(128|192|256)-cbc|arcfour[0-9]*|none" <<< "$ciphers" | paste -sd, -)
        if [[ -n "$weak" ]]; then
            log_crit "Weak / obsolete SSH ciphers enabled: ${weak}. Recommended: chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com."
        else
            log_pass "No legacy SSH ciphers in the effective configuration."
        fi
    fi
    if [[ -n "$macs" ]]; then
        echo -e "  Configured MACs             : ${CYAN}${macs}${NC}"
        weak=$(tr ',' '\n' <<< "$macs" | grep -xEi "hmac-md5(-96)?(-etm@openssh.com)?|hmac-sha1(-96)?|umac-64@openssh.com" | paste -sd, -)
        if [[ -n "$weak" ]]; then
            log_warn "Weak / obsolete SSH MAC algorithms enabled: ${weak}. Recommended: hmac-sha2-512-etm@openssh.com, hmac-sha2-256-etm@openssh.com."
        else
            log_pass "SSH MAC algorithms verified."
        fi
    fi
    if [[ -n "$kex" ]]; then
        echo -e "  Configured KEX Algorithms   : ${CYAN}${kex}${NC}"
        weak=$(grep -oEi "diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1" <<< "$kex" | paste -sd, -)
        if [[ -n "$weak" ]]; then
            log_warn "Weak / obsolete SSH key exchange algorithms enabled: ${weak}. Recommended: curve25519-sha256 and group16+ SHA-2 variants."
        else
            log_pass "SSH key exchange (KEX) algorithms verified."
        fi
    fi
}

section_sshd() {
    if [[ ! -f /etc/ssh/sshd_config && ! -d /etc/ssh/sshd_config.d ]]; then
        echo -e "  OpenSSH daemon config not found (/etc/ssh/sshd_config missing): SSH server is not installed."
        return 0
    fi
    have sshd && SSHD_EFFECTIVE=$(sshd -T 2>/dev/null)
    audit_sshd_directives
    audit_sshd_crypto
}

register_section sshd "SSH Daemon Configuration, Ciphers & Security Directives" section_sshd
