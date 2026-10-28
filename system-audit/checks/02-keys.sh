# SSH keys, Minikube certificates, TLS and OpenSSH certificates.

audit_minikube() {
    subsection "Minikube Certificate Permissions"
    local user uid home shell loose found=0 bad=()
    while IFS=: read -r user uid home shell; do
        [[ -d "$home/.minikube" ]] || continue
        found=1
        loose=$(find "$home/.minikube" -name "*.pem" -perm /077 2>/dev/null)
        [[ -n "$loose" ]] && bad+=("$loose")
    done < <(human_accounts)

    if [[ "$found" -eq 0 ]]; then
        echo "No Minikube profiles found."
    elif [[ ${#bad[@]} -gt 0 ]]; then
        log_warn "Minikube PEM files readable by group/others (fix: --fix):" "${bad[@]}"
    else
        log_pass "Minikube certificate permissions are secure."
    fi
}

audit_ssh_private_keys() {
    subsection "SSH Private Keys: Passphrase Protection & Age (Host & User Keys)"
    local now user uid home shell key entry owner
    local keys=() unprotected=() old=()
    local -A seen=()
    now=$(date +%s)

    # Entries are "owner:path"; host keys use the owner "host" and are never passphrase-protected
    while read -r key; do
        keys+=("host:${key}")
    done < <(find /etc/ssh -maxdepth 1 -type f -name "ssh_host_*_key" 2>/dev/null)
    while IFS=: read -r user uid home shell; do
        [[ -d "$home/.ssh" ]] || continue
        while read -r key; do
            [[ -n "${seen[$key]:-}" ]] && continue
            seen[$key]=1
            grep -q "PRIVATE KEY" "$key" 2>/dev/null && keys+=("${user}:${key}")
        done < <(find "$home/.ssh" -maxdepth 2 -type f ! -name "*.pub" ! -name "known_hosts*" ! -name "authorized_keys*" ! -name "config" 2>/dev/null)
    done < <(all_accounts)

    local user_keys=0 mtime age_days created
    for entry in "${keys[@]}"; do
        owner="${entry%%:*}"
        key="${entry#*:}"
        mtime=$(stat -c %Y "$key" 2>/dev/null) || continue
        age_days=$(( (now - mtime) / 86400 ))
        created=$(date -d "@${mtime}" +%F)

        if [[ "$owner" == "host" ]]; then
            echo -e "  - Host Key: ${CYAN}${key}${NC} | Created/Modified: ${created} (${age_days} days old)"
        else
            user_keys=$((user_keys + 1))
            if have ssh-keygen && ssh-keygen -y -P "" -f "$key" &>/dev/null; then
                unprotected+=("${owner}: ${key}")
            else
                echo -e "  - ${GREEN}Protected SSH Key:${NC} User ${CYAN}${owner}${NC} -> ${key} | Created/Modified: ${created} (${age_days} days old)"
            fi
        fi
        [[ "$age_days" -ge 365 ]] && old+=("${key} (${age_days} days, created ${created})")
    done

    if [[ ${#keys[@]} -eq 0 ]]; then
        log_pass "No SSH private keys found on the system."
        return
    fi
    if [[ ${#unprotected[@]} -gt 0 ]]; then
        log_crit "SSH private keys WITHOUT a passphrase:" "${unprotected[@]}"
    elif [[ "$user_keys" -gt 0 ]]; then
        log_pass "All discovered user SSH private keys (${user_keys}) are protected with passphrases."
    fi
    if [[ ${#old[@]} -gt 0 ]]; then
        log_warn "SSH keys older than 1 year (consider rotation):" "${old[@]}"
    else
        log_pass "All ${#keys[@]} SSH private key(s) are less than 1 year old."
    fi
}

audit_tls_certificates() {
    subsection "SSL/TLS Certificate Expiration (/etc/ssl, /etc/letsencrypt, /etc/pki, ~/.minikube)"
    if ! have openssl; then
        echo -e "${YELLOW}openssl command not available for certificate expiration inspection.${NC}"
        return
    fi
    local now dir cert enddate end_sec days_left user uid home shell valid=0
    local certs=() expired=() expiring=()
    now=$(date +%s)
    for dir in /etc/ssl/certs /etc/pki; do
        [[ -d "$dir" ]] || continue
        while read -r cert; do certs+=("$cert"); done < <(find "$dir" -type f \( -name "*.crt" -o -name "*.pem" -o -name "*.cer" \) 2>/dev/null | head -n 30)
    done
    # Let's Encrypt 'live' entries are symlinks into ../archive
    while read -r cert; do certs+=("$cert"); done < <(find -L /etc/letsencrypt/live -type f -name "cert.pem" 2>/dev/null)
    while IFS=: read -r user uid home shell; do
        [[ -d "$home/.minikube" ]] || continue
        while read -r cert; do certs+=("$cert"); done < <(find "$home/.minikube" -type f \( -name "*.crt" -o -name "*.pem" \) 2>/dev/null | head -n 30)
    done < <(human_accounts)

    for cert in "${certs[@]}"; do
        enddate=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
        [[ -n "$enddate" ]] || continue
        end_sec=$(date -d "$enddate" +%s 2>/dev/null) || continue
        days_left=$(( (end_sec - now) / 86400 ))
        if [[ "$days_left" -lt 0 ]]; then
            expired+=("${cert} (expired ${enddate})")
        elif [[ "$days_left" -le 30 ]]; then
            expiring+=("${cert} (in ${days_left} days, ${enddate})")
        else
            valid=$((valid + 1))
        fi
    done
    [[ ${#expired[@]} -gt 0 ]] && log_crit "EXPIRED certificates:" "${expired[@]}"
    [[ ${#expiring[@]} -gt 0 ]] && log_warn "Certificates expiring within 30 days:" "${expiring[@]}"
    if [[ ${#expired[@]} -eq 0 && ${#expiring[@]} -eq 0 ]]; then
        log_pass "All scanned SSL/TLS certificates (${valid}) are valid and not expiring within 30 days."
    fi
}

audit_ssh_certificates() {
    subsection "OpenSSH Certificate Expiration (*-cert.pub)"
    local scert validity certs=()
    while read -r scert; do certs+=("$scert"); done < <(find /etc/ssh /home /root -name "*-cert.pub" -type f 2>/dev/null)
    if [[ ${#certs[@]} -eq 0 ]]; then
        echo "No OpenSSH certificate files (*-cert.pub) found."
        return
    fi
    for scert in "${certs[@]}"; do
        validity=$(ssh-keygen -L -f "$scert" 2>/dev/null | grep -i "Valid:")
        echo -e "  - OpenSSH Cert ${CYAN}${scert}${NC}: ${validity:-Checked}"
    done
    log_pass "Audited ${#certs[@]} OpenSSH certificate(s)."
}

section_keys_and_certs() {
    audit_minikube
    audit_ssh_private_keys
    audit_tls_certificates
    audit_ssh_certificates
}

register_section keys "SSH Keys, Minikube & TLS/SSH Certificates" section_keys_and_certs
