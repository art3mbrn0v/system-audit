# Pending updates and automatic security updates.

section_updates() {
    subsection "Pending Package Updates"
    if [[ -z "$PKG_MGR" ]]; then
        echo -e "  ${YELLOW}No supported package manager found.${NC}"
        return 0
    fi
    local names security total app key_apps=() auto=false
    names=$(pkg_upgrades | cut -f1)
    security=$(pkg_security_upgrades)
    total=$(count_lines "$names")
    for app in "${KEY_APPS[@]}"; do
        grep -qxF "$app" <<< "$names" && key_apps+=("$app")
    done
    auto_security_updates_enabled && auto=true
    echo -e "  Packages awaiting update: ${CYAN}${total}${NC}, of them security updates: ${CYAN}$(count_lines "$security")${NC}"
    [[ ${#key_apps[@]} -gt 0 ]] && echo -e "  Key applications with updates: ${CYAN}${key_apps[*]}${NC}"

    if [[ -n "$security" ]]; then
        if [[ "$auto" == true ]]; then
            # unattended-upgrades / dnf-automatic installs these on its next daily run
            log_warn "Security updates pending; automatic updates will install them, or run the update now:" "$security"
        else
            log_crit "Security updates pending and NOT installed automatically - known vulnerabilities stay open:" "$security"
        fi
    elif [[ "$total" -gt 0 ]]; then
        log_info "${total} regular (non-security) package update(s) available."
    else
        log_pass "All installed packages are up to date."
    fi

    subsection "Automatic Security Updates"
    if [[ "$auto" == true ]]; then
        log_pass "Automatic security updates are enabled ($([[ "$PKG_MGR" == apt ]] && echo unattended-upgrades || echo dnf-automatic))."
    else
        case "$PKG_MGR" in
            apt) log_warn "Automatic security updates are NOT enabled. Install and enable 'unattended-upgrades'." ;;
            dnf) log_warn "Automatic updates are NOT enabled. Configure dnf-automatic (apply_updates = yes) and enable its timer." ;;
        esac
    fi
}

register_section updates "Pending Package Updates & Automatic Security Updates" section_updates
