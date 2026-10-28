# External auditors: Trivy, Lynis.

section_external_auditors() {
    slow_scan "Trivy and Lynis" || return 0
    if have trivy; then
        echo -e "${CYAN}Running Trivy filesystem scan of ${AUDIT_ROOT}...${NC}"
        trivy fs --severity HIGH,CRITICAL --format table "$AUDIT_ROOT" 2>/dev/null
    else
        echo -e "${DIM}Trivy not installed - optional scanner for code/containers.${NC}"
    fi

    if ! have lynis; then
        echo -e "${YELLOW}Lynis not installed - install lynis for a hardening index and suggestions.${NC}"
        return 0
    fi
    echo -e "\n${CYAN}Running Lynis system audit (quick)...${NC}"
    lynis audit system --quick --no-colors 2>/dev/null | grep -E "Hardening index|Warnings|Suggestions"
    local report=/var/log/lynis-report.dat
    [[ -r "$report" ]] || return 0
    local warnings suggestions
    # Report lines look like "suggestion[]=ID|text|details|solution|"
    warnings=$(grep -E '^warning\[\]=' "$report" | cut -d= -f2- | awk -F'|' '{print $1": "$2}')
    suggestions=$(grep -E '^suggestion\[\]=' "$report" | cut -d= -f2- | awk -F'|' '{d = ($3 != "-" && $3 != "") ? " (" $3 ")" : ""; print $1": "$2 d}')
    [[ -n "$warnings" ]] && log_warn "Lynis warnings:" "$warnings"
    if [[ -n "$suggestions" ]]; then
        echo -e "  Lynis suggestions ($(count_lines "$suggestions"); full list: ${report}):"
        print_details "$suggestions"
    fi
}

register_section auditors "External Auditors (Trivy / Lynis)" section_external_auditors
