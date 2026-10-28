# Shell startup files and the $PATH.

audit_shell_rc_files() {
    subsection "Shell Startup Files: Hijacking Aliases, Remote Execution, Safety Aliases"
    local rc_names=(.bashrc .zshrc .profile .bash_profile .zprofile .bash_aliases .zsh_aliases)
    local hijack_re="alias (sudo|su|ssh|cd|ls|cat|curl|wget)="
    local exec_re="curl.*\|.*(bash|sh)|wget.*\|.*(bash|sh)|eval \\\$\(|base64 -d"
    local user uid home shell rc rc_files hits cmd
    local suspicious=() missing_aliases=()

    while IFS=: read -r user uid home shell; do
        [[ -d "$home" ]] || continue
        rc_files=()
        for rc in "${rc_names[@]}"; do
            [[ -f "$home/$rc" ]] && rc_files+=("$home/$rc")
        done
        [[ ${#rc_files[@]} -gt 0 ]] || continue
        echo -e "  - ${CYAN}${user}${NC}: ${rc_files[*]}"

        hits=$(grep -HEi "$hijack_re" "${rc_files[@]}" 2>/dev/null | grep -v ':[[:space:]]*#' | grep -vE "alias ls='ls --color|alias ll=|alias la=")
        [[ -n "$hits" ]] && suspicious+=("$hits")
        hits=$(grep -HEi "$exec_re" "${rc_files[@]}" 2>/dev/null | grep -v ':[[:space:]]*#')
        [[ -n "$hits" ]] && suspicious+=("$hits")

        # Interactive confirmation aliases only matter for real (human) accounts
        [[ "$uid" -eq 0 || "$uid" -ge 1000 ]] || continue
        for cmd in rm cp mv; do
            grep -Eqs "alias ${cmd}=['\"].*${cmd}.*-i" "${rc_files[@]}" || missing_aliases+=("${user}: alias ${cmd}='${cmd} -i' (add to ${rc_files[0]})")
        done
    done < <(all_accounts)

    if [[ ${#suspicious[@]} -gt 0 ]]; then
        log_warn "Shell startup files redefine sensitive commands or run downloaded/decoded code:" "${suspicious[@]}"
    else
        log_pass "No command-hijacking aliases or download-and-execute patterns in shell startup files."
    fi
    if [[ ${#missing_aliases[@]} -gt 0 ]]; then
        log_info "Safety aliases not configured (--fix adds them for root and the sudo user):" "${missing_aliases[@]}"
    fi
}

audit_path_dirs() {
    subsection "\$PATH Directories (binary hijacking risk)"
    # The PATH this audit was started with (sudo's secure_path), not the one extended in config
    local dirs dir mode owner writable=() bad=()
    IFS=':' read -ra dirs <<< "$ORIGINAL_PATH"
    for dir in "${dirs[@]}"; do
        if [[ -z "$dir" || "$dir" == "." ]]; then
            writable+=("'${dir}' (current directory)")
            continue
        fi
        if [[ ! -d "$dir" ]]; then
            bad+=("${dir} (does not exist)")
            continue
        fi
        mode=$(file_mode "$dir")
        owner=$(stat -L -c %U "$dir" 2>/dev/null)
        if mode_has "$mode" 002; then
            writable+=("${dir} (mode ${mode}, owner ${owner})")
        elif [[ "$owner" != "root" ]]; then
            bad+=("${dir} (owner ${owner}, mode ${mode})")
        fi
    done
    echo "  PATH: ${ORIGINAL_PATH}"
    [[ ${#writable[@]} -gt 0 ]] && log_crit "\$PATH contains world-writable or current directories (anyone can plant commands run by root):" "${writable[@]}"
    [[ ${#bad[@]} -gt 0 ]] && log_warn "\$PATH directories that are missing or not owned by root:" "${bad[@]}"
    if [[ ${#writable[@]} -eq 0 && ${#bad[@]} -eq 0 ]]; then
        log_pass "All \$PATH directories exist, are owned by root and not world-writable."
    fi
}

section_shell_configs() {
    audit_shell_rc_files
    audit_path_dirs
}

register_section shellrc "Shell Config Files (.bashrc, .zshrc), Safety Aliases & \$PATH" section_shell_configs
