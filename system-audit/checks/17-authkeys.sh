# SSH authorized_keys of all accounts.

section_authorized_keys() {
    subsection "SSH Authorized Keys (all accounts)"
    local keys_count=0 user uid home shell auth_file mode is_admin line fields field ktype comment
    local writable=() dsa=() unrestricted=()

    while IFS=: read -r user uid home shell; do
        for auth_file in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [[ -f "$auth_file" ]] || continue
            is_admin=false
            if [[ "$uid" -eq 0 ]] || user_is_admin "$user"; then
                is_admin=true
            fi
            # Public keys may be world-readable; group/world WRITE lets others add their keys
            mode=$(file_mode "$auth_file")
            mode_has "$mode" 022 && writable+=("${auth_file} (mode ${mode})")

            while read -r line; do
                [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
                keys_count=$((keys_count + 1))
                # Options may precede the key type ("from=... ssh-ed25519 AAAA... comment")
                read -ra fields <<< "$line"
                ktype=""
                for field in "${fields[@]}"; do
                    [[ "$field" =~ ^(ssh-|ecdsa-|sk-) ]] && { ktype="$field"; break; }
                done
                comment="${fields[-1]}"
                echo -e "  - ${CYAN}${user}${NC}: ${ktype:-unknown type} '${comment}'$([[ "$line" == *"from="* ]] && echo " (IP-restricted)")"
                [[ "$ktype" == "ssh-dss" ]] && dsa+=("${user}: '${comment}' in ${auth_file}")
                [[ "$is_admin" == true && "$line" != *"from="* ]] && unrestricted+=("${user}: '${comment}'")
            done < "$auth_file"
        done
    done < <(all_accounts)

    if [[ -f /etc/ssh/authorized_keys ]]; then
        local global_cnt
        global_cnt=$(grep -cvE '^[[:space:]]*(#|$)' /etc/ssh/authorized_keys)
        [[ "$global_cnt" -gt 0 ]] && log_warn "Global /etc/ssh/authorized_keys contains ${global_cnt} key(s) - verify they are expected."
    fi

    if [[ "$keys_count" -eq 0 ]]; then
        log_pass "No SSH authorized_keys on this system (no key-based remote logins possible)."
        return
    fi
    [[ ${#writable[@]} -gt 0 ]] && log_crit "authorized_keys files writable by group/others (anyone could add a login key):" "${writable[@]}"
    [[ ${#dsa[@]} -gt 0 ]] && log_crit "Obsolete DSA keys (cryptographically broken) authorized for login:" "${dsa[@]}"
    [[ ${#unrestricted[@]} -gt 0 ]] && log_warn "Keys of administrative accounts without from=\"IP\" restriction (usable from anywhere):" "${unrestricted[@]}"
    [[ ${#writable[@]} -eq 0 && ${#dsa[@]} -eq 0 ]] && log_pass "Audited ${keys_count} authorized key(s): file permissions and key types are fine."
}

register_section authkeys "SSH Authorized Keys (All Users)" section_authorized_keys
