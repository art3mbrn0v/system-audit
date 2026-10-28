# Arguments, section registry, output files, pre-flight and the opt-in changes.

# --- Section registry -----------------------------------------------------------
SECTIONS=()   # "id|title|function" in run order (filled by checks/*.sh)

register_section() {   # register_section ID TITLE FUNCTION
    SECTIONS+=("$1|$2|$3")
}

list_sections() {
    local entry id title fn
    echo "Sections (ids for --only / --skip):"
    for entry in "${SECTIONS[@]}"; do
        IFS='|' read -r id title fn <<< "$entry"
        printf '  %-12s %s\n' "$id" "$title"
    done
}

section_selected() {
    local id=$1
    if [[ -n "$ONLY_SECTIONS" && ",${ONLY_SECTIONS}," != *",${id},"* ]]; then
        return 1
    fi
    [[ ",${SKIP_SECTIONS}," != *",${id},"* ]]
}

validate_section_ids() {
    local id ids entry known=","
    for entry in "${SECTIONS[@]}"; do
        known+="${entry%%|*},"
    done
    IFS=',' read -ra ids <<< "${ONLY_SECTIONS},${SKIP_SECTIONS}"
    for id in "${ids[@]}"; do
        [[ -z "$id" || "$known" == *",${id},"* ]] && continue
        echo "Unknown section id: ${id} (see --list)" >&2
        exit 2
    done
}

# --- Arguments ------------------------------------------------------------------
usage() { awk 'NR > 2 { if (/^# =+$/) exit; sub(/^# ?/, ""); print }' "$AUDIT_ENTRY"; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --fix)              AUTO_FIX=true ;;
            --install)          INSTALL_MISSING_PKGS=true ;;
            --restart-services) AUTO_RESTART_SERVICES=true ;;
            --update-db)        UPDATE_SECURITY_DATABASES=true ;;
            --clean-cache)      CLEAN_CACHE=true ;;
            --clean-history)    CLEAN_HISTORY=true ;;
            --no-dict)          FETCH_EXTERNAL_PASSWORDS=false ;;
            --refresh-dict)     REFRESH_EXTERNAL_PASSWORDS=true ;;
            --quick)            QUICK_MODE=true ;;
            --report-dir|--only|--skip|--exclude)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == -* ]]; then
                    echo "Error: $1 requires a value." >&2
                    exit 2
                fi
                case "$1" in
                    --report-dir) REPORT_DIR="$2" ;;
                    --only)       ONLY_SECTIONS="$2" ;;
                    --skip)       SKIP_SECTIONS="$2" ;;
                    --exclude)    SCAN_EXCLUDES+=("${2%/}") ;;
                esac
                shift
                ;;
            --list)             list_sections; exit 0 ;;
            -h|--help)          usage; exit 0 ;;
            *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
        esac
        shift
    done
    validate_section_ids

    DICT_CACHE_DIR="${REPORT_DIR}/password-dict-cache"
    DICT_FILE="${DICT_CACHE_DIR}/combined-dict.txt"
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as a privileged user (root or via sudo).${NC}" >&2
        exit 1
    fi
}

# --- Output files -----------------------------------------------------------------
setup_output() {
    if ! mkdir -p "$REPORT_DIR" 2>/dev/null; then
        echo -e "${RED}Error: cannot create report directory '${REPORT_DIR}'.${NC}" >&2
        exit 1
    fi
    local stamp
    stamp=$(date +%Y-%m-%d_%H-%M-%S)
    REPORT_FILE="$REPORT_DIR/audit-${stamp}.md"
    LOG_FILE="$REPORT_DIR/audit-${stamp}.log"
    : > "$REPORT_FILE"
    : > "$LOG_FILE"
    chmod 600 "$REPORT_FILE" "$LOG_FILE"
    # Let the invoking user read the results without sudo
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        chown "$SUDO_USER": "$REPORT_FILE" "$LOG_FILE" 2>/dev/null
    fi

    # Private scratch directory: the ONLY place this script creates temp files
    WORK_DIR="$(mktemp -d /tmp/system-audit.XXXXXX)"

    # Everything printed from now on also goes to the log (without colors).
    # tee/sed ignore Ctrl-C/TERM (they stop at end of input), so an interrupted run
    # still gets its last lines into the log.
    exec > >(trap '' INT TERM; tee >(trap '' INT TERM; sed -u -r 's/\x1B\[[0-9;]*[mK]//g' > "$LOG_FILE")) 2>&1
    TEE_PID=$!
    trap on_exit EXIT
    trap on_interrupt INT TERM
}

on_interrupt() {
    AUDIT_INTERRUPTED=true
    echo -e "\n${RED}Audit interrupted.${NC}"
    print_scorecard
    exit 130
}

on_exit() {
    # Close our end of the log pipe and let tee/sed finish before writing the report
    exec >&- 2>&-
    [[ -n "$TEE_PID" ]] && wait "$TEE_PID" 2>/dev/null
    [[ -n "$REPORT_FILE" ]] && write_report
    [[ -n "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
}

print_banner() {
    echo -e "${CYAN}=====================================================${NC}"
    echo -e "${CYAN}=== Starting System Security & Optimization Audit ===${NC}"
    echo -e "${CYAN}=====================================================${NC}"
    echo -e "Audit Version    : ${CYAN}${VERSION}${NC}"
    echo -e "Audit Started At : ${CYAN}${AUDIT_START_TIME_STR}${NC}"
    [[ -n "$ONLY_SECTIONS" ]] && echo -e "Sections (--only): ${CYAN}${ONLY_SECTIONS}${NC}"
    [[ -n "$SKIP_SECTIONS" ]] && echo -e "Skipped (--skip) : ${CYAN}${SKIP_SECTIONS}${NC}"
    echo -e "Scan exclusions  : ${DIM}${SCAN_EXCLUDES[*]}${NC}"
}

# --- Pre-flight -----------------------------------------------------------------
install_tool_package() {   # install_tool_package PACKAGE [SERVICE]
    local pkg="$1" service="${2:-}"
    echo -e "${YELLOW}Installing package '${pkg}' via ${PKG_MGR}...${NC}"
    if pkg_install "$pkg"; then
        log_pass "Package '${pkg}' installed successfully."
        AUDIT_INSTALLED_PKGS["$pkg"]=1
        if [[ "$AUTO_RESTART_SERVICES" == true && -n "$service" ]]; then
            restart_service "$service" "after package installation"
        fi
    else
        log_warn "Failed to install package '${pkg}' via ${PKG_MGR}."
    fi
}

preflight_tools() {
    echo -e "\n${YELLOW}=== Pre-Flight Security Tools & Dependency Check ===${NC}"
    local tool found=0 missing=() scanner_pkgs=() pkg

    for tool in "${TOOLS_TO_CHECK[@]}"; do
        if command -v "$tool" &>/dev/null; then
            TOOL_FOUND["$tool"]=1
            found=$((found + 1))
        else
            TOOL_FOUND["$tool"]=0
        fi
    done
    detect_pkg_mgr

    for tool in "${TOOLS_TO_CHECK[@]}"; do
        [[ "${TOOL_FOUND[$tool]}" -eq 1 ]] && continue
        # The other distribution family's package tools are not "missing"
        case "$PKG_MGR:$tool" in
            apt:dnf|apt:rpm|dnf:apt-get|dnf:dpkg-query|dnf:debsums) continue ;;
        esac
        missing+=("$tool")
        case "$tool" in
            clamscan|freshclam) [[ " ${scanner_pkgs[*]} " == *" clamav "* ]] || scanner_pkgs+=("clamav") ;;
            chkrootkit|nmap|lynis|needrestart|debsums|unhide) scanner_pkgs+=("$tool") ;;
        esac
    done

    echo -e "  [${GREEN}OK${NC}] ${found} of ${#TOOLS_TO_CHECK[@]} tools available (package manager: ${CYAN}${PKG_MGR:-none}${NC})."
    [[ ${#missing[@]} -gt 0 ]] && echo -e "  [${YELLOW}!${NC}] Not installed: ${YELLOW}${missing[*]}${NC}"

    if [[ ${#scanner_pkgs[@]} -gt 0 ]]; then
        if [[ "$INSTALL_MISSING_PKGS" == true && -n "$PKG_MGR" ]]; then
            echo -e "\n${YELLOW}=== Auto-Installing Missing Security Tools ===${NC}"
            for pkg in "${scanner_pkgs[@]}"; do
                if [[ "$pkg" == "clamav" ]]; then
                    install_tool_package clamav clamav-freshclam
                else
                    install_tool_package "$pkg"
                fi
            done
            # Re-resolve: e.g. the 'clamav' package provides clamscan/freshclam
            for tool in "${missing[@]}"; do
                command -v "$tool" &>/dev/null && TOOL_FOUND["$tool"]=1
            done
        else
            case "$PKG_MGR" in
                apt) echo -e "  Recommended: ${CYAN}sudo apt install ${scanner_pkgs[*]}${NC} (or run with --install)" ;;
                dnf) echo -e "  Recommended: ${CYAN}sudo dnf install ${scanner_pkgs[*]}${NC} (or run with --install)" ;;
            esac
        fi
    fi
    if ! have trivy; then
        echo -e "  ${DIM}trivy is optional and not in the Debian repositories - see https://trivy.dev/latest/getting-started/installation/${NC}"
    fi
}

# --- Opt-in changes: --fix, --update-db -----------------------------------------
# Machine-specific fixes from the system runbook (GTK / ALSA / wtmpdb problems seen before)
apply_runbook_fixes() {
    echo -e "${YELLOW}--- Applying System Runbook Automatic Permission & System Fixes ---${NC}"
    local fixes=0

    # 1. PAM wtmpdb SQLite database permissions (/var/log/wtmp.db -> root:utmp 664)
    if [[ -f "/var/log/wtmp.db" ]]; then
        local w_perm w_owner
        w_perm=$(file_mode /var/log/wtmp.db)
        w_owner=$(stat -c "%U:%G" /var/log/wtmp.db 2>/dev/null)
        if [[ "$w_owner" != "root:utmp" || "$w_perm" != "664" ]]; then
            echo -e "  - ${YELLOW}System Runbook Sec 2.3:${NC} Fixing /var/log/wtmp.db permissions (${w_owner} ${w_perm} -> root:utmp 664)..."
            if chown root:utmp /var/log/wtmp.db 2>/dev/null && chmod 664 /var/log/wtmp.db 2>/dev/null; then
                log_pass "Fixed /var/log/wtmp.db permissions to root:utmp 664 (Resolved PAM wtmpdb SQLITE_READONLY error 8)."
                fixes=$((fixes + 1))
            else
                log_warn "Failed to set /var/log/wtmp.db permissions to root:utmp 664."
            fi
        else
            log_pass "/var/log/wtmp.db permissions verified (root:utmp 664)."
        fi
    fi

    # 2. GTK 3 theme parsing error ('!important' in ~/.config/gtk-3.0/gtk.css)
    local user uid home shell gtk_css
    while IFS=: read -r user uid home shell; do
        gtk_css="$home/.config/gtk-3.0/gtk.css"
        if [[ -f "$gtk_css" ]] && grep -q "!important" "$gtk_css" 2>/dev/null; then
            echo -e "  - ${YELLOW}System Runbook Sec 2.1:${NC} Removing '!important' from ${gtk_css} for user ${user}..."
            sed -i 's/\s*!important//g' "$gtk_css" 2>/dev/null
            log_pass "Removed '!important' from ${gtk_css} (Resolved GTK 3 CSS theme parsing errors)."
            fixes=$((fixes + 1))
        fi
    done < <(all_accounts)

    # 3. ALSA restore udev rule: GOTO="alsa_restore_std" has no matching LABEL (the second
    #    LABEL="alsa_restore_go" should be "alsa_restore_std"). Override in /etc unless fixed.
    local alsa_rule="90-alsa-restore.rules" std_label='LABEL="alsa_restore_std"'
    if [[ -f "/usr/lib/udev/rules.d/${alsa_rule}" ]] \
       && ! grep -q "$std_label" "/usr/lib/udev/rules.d/${alsa_rule}" \
       && ! grep -qs "$std_label" "/etc/udev/rules.d/${alsa_rule}"; then
        echo -e "  - ${YELLOW}System Runbook Sec 2.2:${NC} Creating override /etc/udev/rules.d/${alsa_rule} to fix GOTO label mismatch..."
        mkdir -p /etc/udev/rules.d 2>/dev/null
        cp "/usr/lib/udev/rules.d/${alsa_rule}" /etc/udev/rules.d/ 2>/dev/null \
            && sed -i 's/LABEL="alsa_restore_go"/LABEL="alsa_restore_std"/2' "/etc/udev/rules.d/${alsa_rule}" 2>/dev/null
        if grep -qs "$std_label" "/etc/udev/rules.d/${alsa_rule}"; then
            have udevadm && udevadm control --reload-rules 2>/dev/null
            log_pass "Created fixed udev rule /etc/udev/rules.d/${alsa_rule} (LABEL=alsa_restore_std)."
            fixes=$((fixes + 1))
        else
            log_warn "Failed to create the fixed udev rule /etc/udev/rules.d/${alsa_rule}."
        fi
    fi

    [[ "$fixes" -gt 0 ]] && echo -e "  ${GREEN}[OK] Applied ${fixes} runbook-based automatic permission/system fix(es).${NC}"
}

apply_fixes() {
    echo -e "\n${YELLOW}=== Running in Auto-Fix Mode (--fix enabled) ===${NC}"
    local user uid home shell rc alias_cmd

    # Owner-only access for ~/.ssh and Minikube keys of root and regular users
    while IFS=: read -r user uid home shell; do
        if [[ -d "$home/.ssh" ]]; then
            chmod 700 "$home/.ssh" 2>/dev/null
            find "$home/.ssh" -maxdepth 1 -type f -exec chmod 600 {} + 2>/dev/null
        fi
        if [[ -d "$home/.minikube" ]]; then
            find "$home/.minikube" -name "*.pem" -exec chmod 600 {} + 2>/dev/null
        fi
    done < <(human_accounts)

    # Interactive safety aliases for root and the user who ran sudo
    for home in "$HOME" "$(invoking_home)"; do
        [[ -n "$home" ]] || continue
        for rc in "$home/.zshrc" "$home/.bashrc"; do
            [[ -f "$rc" ]] || continue
            for alias_cmd in rm cp mv; do
                grep -q "alias ${alias_cmd}=" "$rc" 2>/dev/null || echo "alias ${alias_cmd}='${alias_cmd} -i'" >> "$rc"
            done
        done
    done

    apply_runbook_fixes
    echo -e "${GREEN}[OK] Auto-fix completed: Permissions, safety aliases & runbook fixes applied.${NC}"
}

update_security_databases() {
    echo -e "\n${YELLOW}--- Updating Security & Audit Tool Databases ---${NC}"
    case "$PKG_MGR" in
        apt)
            echo -n "Updating APT package index... "
            apt-get update -qq 2>/dev/null && echo -e "${GREEN}Done${NC}" || echo -e "${YELLOW}Skipped/Cached${NC}"
            ;;
        dnf)
            echo -n "Refreshing DNF repository metadata... "
            dnf makecache --refresh &>/dev/null && echo -e "${GREEN}Done${NC}" || echo -e "${YELLOW}Skipped/Cached${NC}"
            ;;
    esac
    if have freshclam; then
        if unit_active clamav-freshclam; then
            echo "ClamAV signatures: kept current by the clamav-freshclam daemon - manual freshclam skipped."
        else
            echo -n "Updating ClamAV virus signatures... "
            freshclam --quiet 2>/dev/null && echo -e "${GREEN}Done${NC}" || echo -e "${YELLOW}Failed or locked${NC}"
        fi
    fi
    if have trivy; then
        echo -n "Updating Trivy vulnerability database... "
        trivy image --download-db-only 2>/dev/null && echo -e "${GREEN}Done${NC}" || echo -e "${YELLOW}Skipped/Up to date${NC}"
    fi
}
