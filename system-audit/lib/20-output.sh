# Output, findings and scoring.
#
# A finding is the result of ONE check: log_pass/log_warn/log_crit MESSAGE [DETAIL...].
# Affected objects (files, users, packages ...) go into the DETAIL arguments, so a check
# that finds 160 bad directories is still one finding and weighs once in the score.

PASSED_COUNT=0
WARNING_COUNT=0
CRITICAL_COUNT=0
TOTAL_CHECKS=0

# Finding records (parallel arrays): severity, section title, message, details (\n-separated)
FINDING_SEV=()
FINDING_SECTION=()
FINDING_MSG=()
FINDING_DETAILS=()

SECTION_NO=0
SECTION_TOTAL=0
CURRENT_SECTION=""
SECTION_TIMES=()    # "seconds|title" of finished sections

section()    { SECTION_NO=$((SECTION_NO + 1)); CURRENT_SECTION="$1"; echo -e "\n${BLUE}[${SECTION_NO}/${SECTION_TOTAL}] $1...${NC}"; }
subsection() { echo -e "\n${YELLOW}--- $1 ---${NC}"; }
step()       { echo -e "\n${CYAN}$1${NC}"; }

# print_details DETAIL...: non-empty detail lines, indented, at most MAX_DETAILS of them
print_details() {
    local lines
    lines=$(printf '%s\n' "$@" | sed '/^[[:space:]]*$/d')
    [[ -n "$lines" ]] || return 0
    local count
    count=$(wc -l <<< "$lines")
    head -n "$MAX_DETAILS" <<< "$lines" | sed 's/^/    /'
    [[ "$count" -gt "$MAX_DETAILS" ]] && echo "    ... and $(( count - MAX_DETAILS )) more"
}

record_finding() {   # record_finding SEVERITY MESSAGE DETAIL...
    local sev="$1" msg="$2"
    shift 2
    FINDING_SEV+=("$sev")
    FINDING_SECTION+=("$CURRENT_SECTION")
    FINDING_MSG+=("$msg")
    FINDING_DETAILS+=("$(printf '%s\n' "$@" | sed '/^[[:space:]]*$/d')")
}

log_pass() {
    PASSED_COUNT=$((PASSED_COUNT + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    printf "${GREEN}[OK] %s${NC}\n" "$1"
    print_details "${@:2}"
}

log_warn() {
    WARNING_COUNT=$((WARNING_COUNT + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    record_finding warn "$@"
    printf "${YELLOW}[WARN] %s${NC}\n" "$1"
    print_details "${@:2}"
}

log_crit() {
    CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    record_finding crit "$@"
    printf "${RED}CRITICAL: %s${NC}\n" "$1"
    print_details "${@:2}"
}

# Informational: shown and kept in the report, NOT counted in the score
log_info() {
    record_finding info "$@"
    printf "${CYAN}[INFO] %s${NC}\n" "$1"
    print_details "${@:2}"
}
log_skip() { printf "${YELLOW}[SKIP] %s${NC}\n" "$1"; }

format_duration() {   # format_duration SECONDS
    local s="$1"
    if [[ "$s" -ge 60 ]]; then echo "$(( s / 60 ))m $(( s % 60 ))s"; else echo "${s}s"; fi
}

# Criticals weigh heavily; warnings are capped so many small suggestions cannot zero the score
security_score() {
    local warn_penalty=$(( WARNING_COUNT > 25 ? 25 : WARNING_COUNT ))
    local score=$(( 100 - CRITICAL_COUNT * 12 - warn_penalty ))
    echo $(( score < 0 ? 0 : score ))
}

run_mode() {
    if [[ "$AUTO_FIX" == true || "$INSTALL_MISSING_PKGS" == true || "$UPDATE_SECURITY_DATABASES" == true || "$CLEAN_CACHE" == true \
          || "$CLEAN_HISTORY" == true || "$AUTO_RESTART_SERVICES" == true || "$REFRESH_EXTERNAL_PASSWORDS" == true ]]; then
        echo -n "changes enabled via flags"
    else
        echo -n "report-only (no changes made)"
    fi
    [[ "$QUICK_MODE" == true ]] && echo -n ", quick (slow scanners skipped)"
    echo
}

print_scorecard() {
    local duration score width=20 filled bar color
    duration=$(( $(date +%s) - AUDIT_START_TIME_SEC ))
    score=$(security_score)

    echo -e "\n${CYAN}=====================================================${NC}"
    [[ "$AUDIT_INTERRUPTED" == true ]] && echo -e "${RED}  INTERRUPTED - results cover only the sections completed so far${NC}"
    printf "  %-30s : %s\n" "Audit Started At" "$AUDIT_START_TIME_STR"
    printf "  %-30s : %s\n" "Audit Completed At" "$(date "+%Y-%m-%d %H:%M:%S %Z")"
    printf "  %-30s : %s\n" "Total Execution Duration" "$(format_duration "$duration")"
    echo -e "-----------------------------------------------------"
    printf "  %-30s : %d\n" "Total Security Checks" "$TOTAL_CHECKS"
    printf "  %-30s : ${GREEN}%d${NC}\n" "Checks Passed" "$PASSED_COUNT"
    printf "  %-30s : ${YELLOW}%d${NC}\n" "Warnings / Suggestions" "$WARNING_COUNT"
    printf "  %-30s : ${RED}%d${NC}\n" "Critical Vulnerabilities" "$CRITICAL_COUNT"
    echo -e "-----------------------------------------------------"
    filled=$(( score * width / 100 ))
    bar=$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' $(( width - filled )) '' | tr ' ' '-')
    if [[ "$score" -ge 80 ]]; then color=$GREEN; elif [[ "$score" -ge 50 ]]; then color=$YELLOW; else color=$RED; fi
    echo -e "  Overall Security Score        : ${color}${score}% [${bar}]${NC}"
    if [[ ${#SECTION_TIMES[@]} -gt 0 ]]; then
        echo -e "  Slowest sections              : $(printf '%s\n' "${SECTION_TIMES[@]}" | sort -t'|' -k1,1nr | head -n 3 \
            | awk -F'|' '{printf "%s%s (%ds)", (NR > 1 ? ", " : ""), $2, $1}')"
    fi
    echo -e "${CYAN}=====================================================${NC}"
    if [[ "$AUDIT_INTERRUPTED" == true ]]; then
        echo -e "${RED}Audit interrupted after ${SECTION_NO} of ${SECTION_TOTAL} sections - mode: $(run_mode).${NC}"
    else
        echo -e "${GREEN}[OK] System audit finished - mode: $(run_mode).${NC}"
    fi
    echo -e "  Report (summary & findings) : ${CYAN}${REPORT_FILE}${NC}"
    echo -e "  Full output log             : ${CYAN}${LOG_FILE}${NC}"
    echo -e "${CYAN}=====================================================${NC}"
}

# Markdown text must not break the list layout: backticks -> quotes
md_escape() { sed 's/`/'"'"'/g' <<< "$1"; }

# write_findings_md SEVERITY HEADING: one Markdown list of all findings with that severity
write_findings_md() {
    local sev="$1" heading="$2" i count=0 details lines total
    for i in "${!FINDING_SEV[@]}"; do
        [[ "${FINDING_SEV[$i]}" == "$sev" ]] && count=$((count + 1))
    done
    echo "## ${heading} (${count})"
    echo
    if [[ "$count" -eq 0 ]]; then
        echo "None."
        echo
        return
    fi
    for i in "${!FINDING_SEV[@]}"; do
        [[ "${FINDING_SEV[$i]}" == "$sev" ]] || continue
        echo "- **${FINDING_SECTION[$i]}**: $(md_escape "${FINDING_MSG[$i]}")"
        details="${FINDING_DETAILS[$i]}"
        [[ -n "$details" ]] || continue
        total=$(wc -l <<< "$details")
        lines=$(head -n "$MAX_DETAILS" <<< "$details")
        while IFS= read -r line; do
            echo "  - \`$(sed 's/^[[:space:]]*//; s/`/'"'"'/g' <<< "$line")\`"
        done <<< "$lines"
        [[ "$total" -gt "$MAX_DETAILS" ]] && echo "  - ... and $(( total - MAX_DETAILS )) more (see the log)"
    done
    echo
}

# The Markdown report: run summary, findings by severity, section timings
write_report() {
    local duration score
    duration=$(( $(date +%s) - AUDIT_START_TIME_SEC ))
    score=$(security_score)
    {
        echo "# System Security Audit: $(hostname 2>/dev/null)"
        echo
        [[ "$AUDIT_INTERRUPTED" == true ]] && echo "> **Interrupted** - results cover only the sections completed before the interruption." && echo
        echo "| | |"
        echo "|---|---|"
        echo "| Started | ${AUDIT_START_TIME_STR} |"
        echo "| Duration | $(format_duration "$duration") |"
        echo "| Version / mode | ${VERSION} / $(run_mode) |"
        echo "| Sections | ${SECTION_NO} of ${SECTION_TOTAL}${ONLY_SECTIONS:+ (only: ${ONLY_SECTIONS})}${SKIP_SECTIONS:+ (skipped: ${SKIP_SECTIONS})} |"
        echo "| Checks | ${TOTAL_CHECKS}: ${PASSED_COUNT} passed, ${WARNING_COUNT} warnings, ${CRITICAL_COUNT} critical |"
        echo "| **Security score** | **${score}%** |"
        echo "| Full output | \`$(basename "$LOG_FILE")\` |"
        echo
        write_findings_md crit "Critical findings"
        write_findings_md warn "Warnings"
        write_findings_md info "Notes"
        echo "## Section timings"
        echo
        echo "| Section | Time |"
        echo "|---|---|"
        printf '%s\n' "${SECTION_TIMES[@]}" | sed '/^$/d' | sort -t'|' -k1,1nr \
            | while IFS='|' read -r secs title; do echo "| ${title} | $(format_duration "$secs") |"; done
    } > "$REPORT_FILE"
}
