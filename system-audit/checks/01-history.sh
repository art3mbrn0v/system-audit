# Shell history: secrets typed on the command line.

clean_history_file() {   # clean_history_file FILE REGEX
    local file="$1" regex="$2" tmp
    echo "Processing ${file}..."
    tmp=$(mktemp -p "$WORK_DIR")
    # grep fails when nothing would be left or the file is unreadable: never truncate then
    if grep -vEia -- "$regex" "$file" > "$tmp" 2>/dev/null && ! cmp -s "$tmp" "$file"; then
        # Keep a backup so the cleanup is reversible
        cp -p "$file" "${file}.audit-backup" 2>/dev/null && chmod 600 "${file}.audit-backup"
        cat "$tmp" > "$file"
    fi
    rm -f "$tmp"
    chmod 600 "$file"
}

section_shell_history() {
    local regex user uid home shell f n hits=0 files=() hit_files=()
    regex=$(IFS="|"; echo "${SENSITIVE_PATTERNS[*]}")

    while IFS=: read -r user uid home shell; do
        for f in "$home/.zsh_history" "$home/.bash_history"; do
            [[ -f "$f" ]] && files+=("$f")
        done
    done < <(human_accounts)
    [[ ${#files[@]} -gt 0 ]] && mapfile -t files < <(printf '%s\n' "${files[@]}" | sort -u)

    if [[ "$CLEAN_HISTORY" == true ]]; then
        for f in "${files[@]}"; do
            clean_history_file "$f" "$regex"
        done
        log_pass "Shell history cleaned (backups: *.audit-backup, mode 600)."
        return
    fi

    for f in "${files[@]}"; do
        n=$(grep -ciEa -- "$regex" "$f" 2>/dev/null)
        [[ "${n:-0}" -gt 0 ]] && hit_files+=("${f}: ${n} line(s)")
        hits=$(( hits + ${n:-0} ))
    done
    if [[ "$hits" -gt 0 ]]; then
        log_warn "${hits} shell-history line(s) contain keywords such as password/token/secret (review them; --clean-history removes them, backup is kept)." "${hit_files[@]}"
    else
        log_pass "No sensitive keywords found in shell history files (${#files[@]} file(s) checked)."
    fi
}

register_section history "Shell History: Sensitive Data in Command Lines" section_shell_history
