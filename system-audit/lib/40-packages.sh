# Package manager layer (apt / dnf).

detect_pkg_mgr() {
    if have apt-get; then
        PKG_MGR=apt
    elif have dnf; then
        PKG_MGR=dnf
    fi
}

pkg_installed() {
    case "$PKG_MGR" in
        apt) [[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null)" == *"ok installed" ]] ;;
        dnf) rpm -q "$1" &>/dev/null ;;
        *)   return 1 ;;
    esac
}

# pkg_owner FILE: package that ships FILE (empty if none)
pkg_owner() {
    case "$PKG_MGR" in
        apt) dpkg -S "$1" 2>/dev/null | head -n 1 | cut -d: -f1 ;;
        dnf) rpm -qf "$1" 2>/dev/null | grep -v 'not owned' | head -n 1 ;;
    esac
}

pkg_install() {
    case "$PKG_MGR" in
        apt) apt-get install -y "$1" 2>/dev/null ;;
        dnf) dnf install -y "$1" 2>/dev/null ;;
        *)   return 1 ;;
    esac
}

# Pending upgrades, queried once per run: "name<TAB>origin" per package.
# apt origin looks like "1.2-3 Debian-Security:13/stable-security [amd64])".
PKG_UPGRADES=""
PKG_UPGRADES_LOADED=false
pkg_upgrades() {
    if [[ "$PKG_UPGRADES_LOADED" != true ]]; then
        PKG_UPGRADES_LOADED=true
        case "$PKG_MGR" in
            apt) PKG_UPGRADES=$(apt-get -s dist-upgrade 2>/dev/null | awk '/^Inst / {name = $2; sub(/^[^(]*\(/, ""); print name "\t" $0}') ;;
            dnf) PKG_UPGRADES=$(dnf -q check-update 2>/dev/null | awk 'NF == 3 && $1 ~ /\./ {name = $1; sub(/\.[^.]+$/, "", name); print name "\t" $2 " " $3}') ;;
        esac
    fi
    [[ -n "$PKG_UPGRADES" ]] && printf '%s\n' "$PKG_UPGRADES"
}

# Names of packages with a pending SECURITY update
pkg_security_upgrades() {
    case "$PKG_MGR" in
        apt) pkg_upgrades | awk -F'\t' '$2 ~ /-security|Security/ {print $1}' ;;
        # --security lists advisories whose fix is available but not installed yet
        dnf) dnf -q updateinfo list --security 2>/dev/null | awk 'NF >= 3 {print $3}' | sort -u ;;
    esac
}

# Automatic installation of security updates is configured and active
auto_security_updates_enabled() {
    case "$PKG_MGR" in
        apt) unit_active unattended-upgrades \
             || grep -qsE 'APT::Periodic::Unattended-Upgrade[[:space:]]+"1"' /etc/apt/apt.conf.d/20auto-upgrades ;;
        dnf) unit_active dnf-automatic.timer || unit_active dnf-automatic-install.timer || unit_active dnf5-automatic.timer \
             || grep -qsE '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*(yes|true|1)' /etc/dnf/automatic.conf ;;
        *)   return 1 ;;
    esac
}
