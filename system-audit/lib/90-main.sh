# Wrap-up and the main flow.

report_footprint() {
    echo -e "\n${YELLOW}=== Post-Audit Summary: What This Run Left on the System ===${NC}"
    # Packages installed by --install are KEPT (scanners stay available for future runs)
    local pkg installed=("${!AUDIT_INSTALLED_PKGS[@]}")
    if [[ ${#installed[@]} -gt 0 ]]; then
        echo -e "  Packages installed by this audit run (KEPT on the system):"
        for pkg in "${installed[@]}"; do
            echo -e "    - ${CYAN}${pkg}${NC}"
        done
        echo -e "  ${YELLOW}Tip: to remove them later:${NC} ${PKG_MGR} remove ${installed[*]}"
        case "$PKG_MGR" in
            apt) apt-get clean 2>/dev/null && echo -e "  ${GREEN}OK${NC} APT archive cache cleaned (/var/cache/apt/archives)." ;;
            dnf) dnf clean all &>/dev/null && echo -e "  ${GREEN}OK${NC} DNF cache cleaned." ;;
        esac
    else
        echo -e "  No packages were installed by this audit run - the system package set is unchanged."
    fi

    # Leftovers of an interrupted dictionary download ($WORK_DIR is removed on exit)
    find "$REPORT_DIR" "$DICT_CACHE_DIR" -maxdepth 1 -name "*.tmp" -type f -delete 2>/dev/null

    [[ -s "$DICT_FILE" ]] && echo -e "  Password dictionary cache: ${CYAN}${DICT_FILE}${NC}"
    [[ "$CLEAN_HISTORY" == true ]] && echo -e "  History backups: *.audit-backup (contain the removed lines - delete when no longer needed)"
    [[ "$AUTO_FIX" == true ]] && echo -e "  Remediations: permission/config fixes applied by --fix (see [OK] lines above)"
}

run_sections() {
    local entry id title fn started elapsed selected=()
    for entry in "${SECTIONS[@]}"; do
        section_selected "${entry%%|*}" && selected+=("$entry")
    done
    SECTION_TOTAL=${#selected[@]}
    for entry in "${selected[@]}"; do
        IFS='|' read -r id title fn <<< "$entry"
        section "$title"
        started=$SECONDS
        "$fn"
        elapsed=$(( SECONDS - started ))
        SECTION_TIMES+=("${elapsed}|${title}")
        echo -e "${DIM}  (section finished in $(format_duration "$elapsed"))${NC}"
    done
}

main() {
    parse_args "$@"
    require_root

    AUDIT_START_TIME_SEC=$(date +%s)
    AUDIT_START_TIME_STR=$(date "+%Y-%m-%d %H:%M:%S %Z")
    setup_output
    print_banner
    preflight_tools

    [[ "$AUTO_FIX" == true ]] && apply_fixes
    if [[ "$UPDATE_SECURITY_DATABASES" == true ]]; then
        update_security_databases
    else
        echo -e "${DIM}Security database refresh skipped (report-only). Use --update-db to refresh APT/ClamAV/Trivy databases.${NC}"
    fi

    run_sections
    report_footprint
    print_scorecard

    [[ "$CRITICAL_COUNT" -gt 0 ]] && exit 1
    exit 0
}
