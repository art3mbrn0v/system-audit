# User accounts, groups, passwords, sudoers and PAM.

audit_passwd_entries() {
    subsection "/etc/passwd Accounts & Interactive Shells"
    local uid_zero dup_uids dup_users legacy
    uid_zero=$(awk -F: '$3 == "0" && $1 != "root" {print $1}' /etc/passwd)
    dup_uids=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
    dup_users=$(cut -d: -f1 /etc/passwd | sort | uniq -d)
    legacy=$(awk -F: '$2 != "x" && $2 != "*" && $2 != "!" {print $1}' /etc/passwd)
    if [[ -n "$uid_zero" ]]; then log_crit "Non-root accounts with UID 0:" "$uid_zero"; else log_pass "Only 'root' has UID 0."; fi
    if [[ -n "$dup_uids$dup_users" ]]; then
        log_crit "Duplicate UIDs or user names in /etc/passwd:" "$dup_uids" "$dup_users"
    else
        log_pass "No duplicate UIDs or user names in /etc/passwd."
    fi
    if [[ -n "$legacy" ]]; then
        log_crit "Accounts with password hashes directly in /etc/passwd:" "$legacy"
    else
        log_pass "All password hashes are in /etc/shadow (shadow mode active)."
    fi

    step "Accounts with an interactive login shell:"
    local user uid gid home shell sudo_state pw_state
    local sys_interactive=() bad_shells=() bad_homes=() bad_gids=()
    while IFS=: read -r user _ uid gid _ home shell; do
        has_login_shell "$shell" || continue
        sudo_state="no"
        if [[ "$uid" -eq 0 ]]; then
            sudo_state="${RED}root${NC}"
        elif user_is_admin "$user"; then
            sudo_state="${YELLOW}yes (sudo group)${NC}"
        fi
        case "$(passwd -S "$user" 2>/dev/null | awk '{print $2}')" in
            L|LK) pw_state="${YELLOW}locked${NC}" ;;
            P|PS) pw_state="${GREEN}set${NC}" ;;
            NP)   pw_state="${RED}NO PASSWORD${NC}" ;;
            *)    pw_state="unknown" ;;
        esac
        echo -e "  - ${CYAN}${user}${NC} (UID ${uid}, shell ${shell}, home ${home}) | sudo: ${sudo_state} | password: ${pw_state}"

        [[ "$uid" -ne 0 && "$uid" -lt 1000 ]] && sys_interactive+=("${user} (UID ${uid})")
        [[ -x "$shell" ]] || bad_shells+=("${user}: ${shell}")
        if [[ "$home" == "/" || "$home" =~ ^/(tmp|var/tmp|dev/shm) || ! -d "$home" ]]; then
            bad_homes+=("${user}: ${home}")
        fi
        awk -F: -v g="$gid" '$3 == g {found = 1} END {exit !found}' /etc/group || bad_gids+=("${user}: GID ${gid}")
    done < /etc/passwd

    if [[ ${#sys_interactive[@]} -gt 0 ]]; then
        log_warn "System accounts (UID < 1000) with interactive login shells:" "${sys_interactive[@]}"
    else
        log_pass "No system service accounts have interactive login shells."
    fi
    [[ ${#bad_shells[@]} -gt 0 ]] && log_warn "Accounts with a missing or non-executable shell:" "${bad_shells[@]}"
    [[ ${#bad_gids[@]} -gt 0 ]] && log_warn "Accounts whose primary group does not exist in /etc/group:" "${bad_gids[@]}"
    if [[ ${#bad_homes[@]} -gt 0 ]]; then
        log_warn "Interactive accounts with a missing or suspicious home directory:" "${bad_homes[@]}"
    else
        log_pass "All interactive accounts have valid home directories."
    fi
}

audit_groups() {
    subsection "Privileged Groups"
    local dup_gids dup_names zero_gids
    dup_gids=$(cut -d: -f3 /etc/group | sort | uniq -d)
    dup_names=$(cut -d: -f1 /etc/group | sort | uniq -d)
    zero_gids=$(awk -F: '$3 == "0" && $1 != "root" {print $1}' /etc/group)
    if [[ -n "$dup_gids$dup_names" ]]; then
        log_warn "Duplicate GIDs or group names in /etc/group:" "$dup_gids" "$dup_names"
    else
        log_pass "No duplicate GIDs or group names in /etc/group."
    fi
    [[ -n "$zero_gids" ]] && log_warn "Non-root groups with GID 0:" "$zero_gids"

    local grp line gid members primary all risky=()
    for grp in sudo wheel admin docker podman shadow disk kmem input kvm adm systemd-journal; do
        line=$(grep -m1 "^${grp}:" /etc/group) || continue
        gid=$(cut -d: -f3 <<< "$line")
        members=$(cut -d: -f4 <<< "$line")
        # Users whose PRIMARY group this is are members too
        primary=$(awk -F: -v g="$gid" '$4 == g {print $1}' /etc/passwd | paste -sd, -)
        all=$(printf '%s\n%s\n' "$primary" "$members" | tr ',' '\n' | sed '/^$/d' | sort -u | paste -sd, -)
        echo -e "  - ${CYAN}${grp}${NC} (GID ${gid}): ${all:-(no members)}"
        [[ -n "$all" ]] || continue
        case "$grp" in
            docker|podman)    risky+=("${grp}: ${all} (root-equivalent: can mount the host filesystem into a container)") ;;
            shadow|disk|kmem) risky+=("${grp}: ${all} (raw disk / password hash access)") ;;
        esac
    done
    [[ ${#risky[@]} -gt 0 ]] && log_warn "Members of root-equivalent groups:" "${risky[@]}"
}

audit_user_privileges() {
    subsection "Per-User Privileges & Login Counts"
    local -A login_count=() last_login=()
    local name rest
    # wtmp records per user (reboot/shutdown pseudo-users excluded)
    while read -r name rest; do
        [[ -z "$name" || "$name" == "reboot" || "$name" == "shutdown" ]] && continue
        login_count[$name]=$(( ${login_count[$name]:-0} + 1 ))
        [[ -z "${last_login[$name]:-}" ]] && last_login[$name]=$(awk '{for (i = 2; i <= NF; i++) printf "%s ", $i}' <<< "$rest")
    done < <(wtmp_log)

    local user uid home shell groups priv total=0 privileged=0
    while IFS=: read -r user uid home shell; do
        [[ "$uid" -eq 65534 ]] && continue
        [[ "$uid" -ge 1000 || "$uid" -eq 0 || "$shell" =~ (bash|zsh|sh|csh|tcsh|ksh)$ ]] || continue
        total=$((total + 1))
        groups=$(id -Gn "$user" 2>/dev/null | tr ' ' ',')
        priv=""
        [[ "$uid" -eq 0 ]] && priv+=" [ROOT]"
        [[ ",${groups}," =~ ,(sudo|wheel|admin), ]] && priv+=" [SUDO]"
        [[ ",${groups}," =~ ,(docker|containerd|podman), ]] && priv+=" [CONTAINER HOST]"
        [[ ",${groups}," =~ ,(shadow|disk|kmem), ]] && priv+=" [RAW DISK/SHADOW]"
        [[ -n "$priv" ]] && privileged=$((privileged + 1))
        echo -e "  - ${CYAN}${user}${NC} (UID ${uid})${priv:+${RED}${priv}${NC}} | groups: ${groups:-?}"
        echo -e "    logins: ${login_count[$user]:-0}, last: ${last_login[$user]:-none recorded}"
    done < <(all_accounts)

    if [[ "$privileged" -gt 2 ]]; then
        log_warn "${privileged} privileged accounts (root included) out of ${total}. Review who really needs sudo/docker."
    else
        log_pass "Privileged accounts: ${privileged} of ${total} (root + the expected admin user)."
    fi
}

fetch_external_password_lists() {
    echo -e "${YELLOW}--- Weak Password Dictionary Cache (GitHub sources) ---${NC}"
    mkdir -p "$DICT_CACHE_DIR" 2>/dev/null
    chmod 700 "$DICT_CACHE_DIR" 2>/dev/null

    # Do not touch the network/cache unless explicitly requested
    if [[ "$REFRESH_EXTERNAL_PASSWORDS" != true ]]; then
        if [[ -s "$DICT_FILE" ]]; then
            echo -e "  Using the cached dictionary (refresh with --refresh-dict)."
        else
            echo -e "  ${YELLOW}No cached dictionary; only built-in common passwords are tried (download with --refresh-dict).${NC}"
        fi
        return 0
    fi
    if ! have curl && ! have wget; then
        echo -e "  ${YELLOW}Neither curl nor wget available: cannot refresh the dictionary cache.${NC}"
        return 0
    fi

    local start elapsed url fname dest local_size downloaded=0 skipped=0 failed=0 raw_files=()
    start=$(date +%s)
    for url in "${EXTERNAL_PASSWORD_LIST_URLS[@]}"; do
        elapsed=$(( $(date +%s) - start ))
        if [[ "$elapsed" -ge "$DICT_DOWNLOAD_TIMEOUT_SEC" ]]; then
            echo -e "  ${YELLOW}Download budget (${DICT_DOWNLOAD_TIMEOUT_SEC}s) reached; continuing with sources fetched so far.${NC}"
            break
        fi
        fname="${url##*/}"
        dest="$DICT_CACHE_DIR/$fname"
        # Cache hit: the cached file size matches the remote size
        if [[ -s "$dest" ]]; then
            local_size=$(stat -c %s "$dest" 2>/dev/null)
            if [[ "$(remote_size "$url")" == "$local_size" ]]; then
                echo -e "  - ${fname}: cache up to date (${local_size} bytes)"
                skipped=$((skipped + 1))
                raw_files+=("$dest")
                continue
            fi
        fi
        echo -n "  - Downloading ${fname}... "
        if fetch_url "$url" "$dest" $(( DICT_DOWNLOAD_TIMEOUT_SEC - elapsed )); then
            echo -e "${GREEN}OK${NC} ($(stat -c %s "$dest") bytes)"
            downloaded=$((downloaded + 1))
            raw_files+=("$dest")
        else
            echo -e "${YELLOW}FAILED${NC}"
            failed=$((failed + 1))
            [[ -s "$dest" ]] && raw_files+=("$dest")
        fi
    done

    if [[ ${#raw_files[@]} -gt 0 ]]; then
        cat "${raw_files[@]}" 2>/dev/null | tr -d '\r' | grep -vE '^[[:space:]]*(#|$)' | sort -u > "${DICT_FILE}.tmp"
        if [[ -s "${DICT_FILE}.tmp" ]]; then
            mv -f "${DICT_FILE}.tmp" "$DICT_FILE"
            chmod 600 "$DICT_FILE"
            echo -e "  Combined dictionary: $(wc -l < "$DICT_FILE") unique passwords."
        else
            rm -f "${DICT_FILE}.tmp"
            echo -e "  ${YELLOW}Building the combined dictionary failed (kept the previous one).${NC}"
        fi
    fi
    echo -e "  Sources: ${downloaded} downloaded, ${skipped} reused from cache, ${failed} failed."
}

audit_weak_passwords() {
    if ! have python3; then
        echo -e "${YELLOW}python3 not installed: weak password check skipped.${NC}"
        return 0
    fi
    slow_scan "Weak-password dictionary check" || return 0
    local dict_arg="" result value rc
    if [[ "$FETCH_EXTERNAL_PASSWORDS" == true ]]; then
        fetch_external_password_lists
        dict_arg="$DICT_FILE"
    fi
    echo -e "${CYAN}Trying common and dictionary passwords against the shadow hashes...${NC}"
    result=$(timeout 600s python3 -I "${AUDIT_LIB}/weak_passwords.py" "$(hostname 2>/dev/null)" "$dict_arg" "${SHADOW_FILE:-/etc/shadow}" 2>"$WORK_DIR/weak_passwords.err")
    rc=$?
    # TOTAL_PASSWORDS is printed last: without it the scan stopped half-way
    if [[ "$rc" -ne 0 ]] || ! matches '^TOTAL_PASSWORDS:' "$result"; then
        log_warn "Weak-password check did not complete ($([[ "$rc" -eq 124 ]] && echo "timeout" || echo "exit code ${rc}")): result unknown." \
            "$(tail -n 3 "$WORK_DIR/weak_passwords.err" 2>/dev/null)"
        return 0
    fi

    value=$(sed -n 's/^DICT_ERR://p' <<< "$result")
    [[ -n "$value" ]] && echo -e "  ${YELLOW}Could not read ${DICT_FILE}: ${value}${NC}"
    echo -e "  Passwords tried per account: ${CYAN}$(sed -n 's/^TOTAL_PASSWORDS://p' <<< "$result")${NC}"

    local algos weak partial
    algos=$(sed -n 's/^ALGOS://p' <<< "$result")
    if [[ -n "$algos" ]]; then
        echo -e "  Password hashing algorithms in use: ${CYAN}${algos}${NC}"
        matches 'MD5|DES' "$algos" && log_warn "Obsolete password hashes (MD5/DES) in /etc/shadow - change those passwords to get yescrypt/SHA-512 hashes." "$algos"
    fi
    weak=$(sed -n 's/^WEAK://p' <<< "$result")
    partial=$(sed -n 's/^PARTIAL://p' <<< "$result")
    if [[ -n "$weak" ]]; then
        # The matched password itself is never written into the report
        log_crit "Accounts with a common / dictionary password (change immediately):" "$weak"
    elif matches '^CRYPT_AVAILABLE:0' "$result"; then
        log_warn "Weak-password check could not run: libcrypt is not loadable from python3 (result unknown)."
    elif [[ -n "$partial" ]]; then
        log_warn "Weak-password check hit its time budget (partial coverage, user:tested:total):" "$partial"
    else
        log_pass "No account uses a common or dictionary password."
    fi
}

audit_shadow_passwords() {
    subsection "Passwords: Empty, Weak and Expired"
    if [[ ! -r /etc/shadow ]]; then
        log_warn "Cannot read /etc/shadow (root required): password checks skipped."
        return 0
    fi
    local empty
    empty=$(awk -F: '$2 == "" || $2 == "NP" {print $1}' /etc/shadow)
    if [[ -n "$empty" ]]; then
        log_crit "Accounts with NO password in /etc/shadow:" "$empty"
    else
        log_pass "No account has an empty password field."
    fi

    audit_weak_passwords

    local today expired=() no_max=() user pass lstchg max
    today=$(( $(date +%s) / 86400 ))
    while IFS=: read -r user pass lstchg _ max _; do
        [[ -z "$user" || "$pass" == [\!\*]* ]] && continue
        if [[ "$max" =~ ^[0-9]+$ && "$max" -ne 99999 && "$lstchg" =~ ^[0-9]+$ && "$lstchg" -gt 0 ]]; then
            [[ "$today" -ge $(( lstchg + max )) ]] && expired+=("${user} (expired $(( today - lstchg - max )) days ago)")
        elif [[ -z "$max" || "$max" == "99999" ]]; then
            no_max+=("$user")
        fi
    done < /etc/shadow
    if [[ ${#expired[@]} -gt 0 ]]; then
        log_warn "Accounts with EXPIRED passwords:" "${expired[@]}"
    else
        log_pass "No active account has an expired password."
    fi
    [[ ${#no_max[@]} -gt 0 ]] && echo -e "  Accounts without password expiry (normal per NIST SP 800-63B): ${CYAN}${no_max[*]}${NC}"
}

# login_def KEY: value of KEY in /etc/login.defs (empty if unset)
login_def() { awk -v k="$1" '$1 == k {print $2; exit}' /etc/login.defs 2>/dev/null; }

audit_login_defs() {
    subsection "Password & UMASK Policy (/etc/login.defs)"
    [[ -f /etc/login.defs ]] || return 0
    local max min umask enc
    max=$(login_def PASS_MAX_DAYS)
    min=$(login_def PASS_MIN_DAYS)
    umask=$(login_def UMASK)
    enc=$(login_def ENCRYPT_METHOD)
    echo -e "  PASS_MAX_DAYS ${CYAN}${max:-99999}${NC}, PASS_MIN_DAYS ${CYAN}${min:-0}${NC}, PASS_WARN_AGE ${CYAN}$(login_def PASS_WARN_AGE)${NC}, UMASK ${CYAN}${umask:-022 (default)}${NC}, ENCRYPT_METHOD ${CYAN}${enc:-YESCRYPT}${NC}"

    if [[ "${umask:-022}" =~ ^0?(022|002|000)$ ]]; then
        log_warn "Default UMASK is ${umask:-022}: new files are readable by group/others. Recommended: 027 or 077 (UMASK in /etc/login.defs)."
    else
        log_pass "Default UMASK is restrictive (${umask})."
    fi
    if [[ "$enc" =~ DES|MD5 ]]; then
        log_crit "Obsolete password hashing method ENCRYPT_METHOD=${enc} in /etc/login.defs. Use YESCRYPT or SHA512."
    fi
}

audit_sudoers() {
    subsection "Sudoers: NOPASSWD, Dangerous Rules, Drop-in Permissions"
    # /etc/sudoers permissions are covered by the filesystem matrix; drop-ins are checked here
    local files=(/etc/sudoers) sf mode hits
    local bad_perms=() nopasswd=() gtfobins=() env_keep=()
    local gtfobins_re="find|vim|vi|less|more|nmap|python|python3|perl|php|awk|bash|sh|env|gdb|strace|tcpdump"
    while read -r sf; do files+=("$sf"); done < <(find /etc/sudoers.d -type f 2>/dev/null)

    for sf in "${files[@]}"; do
        [[ -r "$sf" ]] || continue
        if [[ "$sf" != "/etc/sudoers" ]]; then
            mode=$(file_mode "$sf")
            [[ "$mode" =~ ^(440|400)$ ]] || bad_perms+=("${sf} (mode ${mode})")
        fi
        hits=$(grep -HEi "NOPASSWD[[:space:]]*:" "$sf" 2>/dev/null | grep -v ':[[:space:]]*#')
        [[ -n "$hits" ]] && nopasswd+=("$hits")
        hits=$(grep -HEi "NOPASSWD.*\b(${gtfobins_re})\b" "$sf" 2>/dev/null | grep -v ':[[:space:]]*#')
        [[ -n "$hits" ]] && gtfobins+=("$hits")
        hits=$(grep -HEi "env_keep.*\b(LD_PRELOAD|PATH|PYTHONPATH|PERL5LIB)\b" "$sf" 2>/dev/null | grep -v ':[[:space:]]*#')
        [[ -n "$hits" ]] && env_keep+=("$hits")
    done

    [[ ${#bad_perms[@]} -gt 0 ]] && log_warn "sudoers drop-ins with non-standard permissions (expected 440):" "${bad_perms[@]}"
    if [[ ${#nopasswd[@]} -gt 0 ]]; then
        log_warn "NOPASSWD rules in sudoers:" "${nopasswd[@]}"
    else
        log_pass "No NOPASSWD rules in sudoers."
    fi
    [[ ${#gtfobins[@]} -gt 0 ]] && log_crit "NOPASSWD sudo rules allow shell-escape binaries (GTFOBins) - instant root:" "${gtfobins[@]}"
    [[ ${#env_keep[@]} -gt 0 ]] && log_crit "sudoers keeps LD_PRELOAD/PATH-like variables (library/binary injection into sudo):" "${env_keep[@]}"
}

audit_pam() {
    subsection "PAM Authentication Stack (/etc/pam.d)"
    [[ -d /etc/pam.d ]] || return 0
    local permit exec_hooks foreign
    permit=$(grep -HEi "^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_permit\.so" /etc/pam.d/* 2>/dev/null)
    exec_hooks=$(grep -HEi "pam_exec\.so" /etc/pam.d/* 2>/dev/null | grep -v ':[[:space:]]*#')
    foreign=$(grep -HEi "\.so" /etc/pam.d/* 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/|/home/")
    if [[ -n "$permit" ]]; then
        log_crit "PAM authentication bypass (auth sufficient pam_permit.so):" "$permit"
    else
        log_pass "No unconditional pam_permit bypass in the PAM stack."
    fi
    if [[ -n "$exec_hooks" ]]; then
        log_warn "pam_exec.so hooks in PAM (can capture passwords - verify they are yours):" "$exec_hooks"
    else
        log_pass "No pam_exec.so hooks in PAM."
    fi
    [[ -n "$foreign" ]] && log_crit "PAM loads modules from temporary/user directories:" "$foreign"
}

section_accounts() {
    audit_passwd_entries
    audit_groups
    audit_user_privileges
    audit_shadow_passwords
    audit_login_defs
    audit_sudoers
    audit_pam
}

register_section accounts "User Accounts, Groups, Passwords, Sudoers & PAM" section_accounts
