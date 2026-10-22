#!/usr/bin/env bash
# ==============================================================================
# System Security & Optimization Audit (Debian / Ubuntu / Fedora family)
#
# Usage: sudo ./system-audit.sh [options]
#   (no options)         audit/report mode; no system remediation is performed
#   --fix                apply safe permission/config remediations
#   --install            install missing scanner packages (apt/dnf)
#   --restart-services   restart services reported by needrestart / failed units
#   --update-db          refresh APT/ClamAV/Trivy security databases
#   --clean-cache        delete reclaimable user caches (thumbnails, pip, npm ...)
#   --clean-history      remove lines with secrets from shell history (backup kept)
#   --no-dict            disable the weak-password dictionary check
#   --refresh-dict       refresh the external weak-password dictionary cache
#   --report-dir DIR     where to write the report (default: ./reports)
#   --only IDS           run only these sections (comma-separated ids, see --list)
#   --skip IDS           run all sections except these
#   --list               list section ids and exit
#   -h, --help           show this help
# Exit code: 0 = no critical findings, 1 = critical findings, 2 = usage error
# ==============================================================================

# Locale-independent parsing of tool output (ss, last, passwd -S, top, ...)
export LC_ALL=C
umask 077
# With pipefail, `producer | grep -q` reports failure whenever grep exits early and the
# producer dies of SIGPIPE. Never test such a pipeline: capture the text, then use matches().
set -o pipefail

VERSION="3.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Resolve sbin tools even when sudo/su did not set a root PATH (the $PATH audit checks the original)
ORIGINAL_PATH="$PATH"
PATH="/usr/local/sbin:/usr/sbin:/sbin:${PATH}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Run modes: safe by default, the audit only READS. Every change is opt-in via a flag ---
AUTO_FIX=false
CLEAN_CACHE=false
CLEAN_HISTORY=false
AUTO_RESTART_SERVICES=false
INSTALL_MISSING_PKGS=false
UPDATE_SECURITY_DATABASES=false
FETCH_EXTERNAL_PASSWORDS=true
REFRESH_EXTERNAL_PASSWORDS=false
REPORT_DIR="${SCRIPT_DIR}/reports"
ONLY_SECTIONS=""
SKIP_SECTIONS=""

# Shell-history keywords that suggest a secret was typed on the command line
SENSITIVE_PATTERNS=(
    "password" "secret" "token" "passwd" "auth.db"
    "credentials" "api_key" "access_key" "private_key" "id_rsa"
    "account_info" "pass_keys" "access_keys"
)

# Public weak-password lists. Cached under the report dir as raw files + one combined,
# deduplicated dictionary; downloaded only with --refresh-dict.
EXTERNAL_PASSWORD_LIST_URLS=(
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/500-worst-passwords.txt"
    "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top12Thousand-probable-v2.txt"
)
DICT_DOWNLOAD_TIMEOUT_SEC=300   # overall download budget: 5 minutes

# Applications whose pending updates are named explicitly in the updates section
KEY_APPS=("code" "google-chrome-stable" "firefox" "firefox-esr" "docker-ce" "docker-ce-cli" "docker-cli" "kubernetes1.34-client" "clamav")

# Tools looked up in the pre-flight check
TOOLS_TO_CHECK=(
    "sudo" "systemctl" "journalctl" "ss" "sysctl" "ssh-keygen"
    "crontab" "ip" "df" "awk" "grep" "sed" "find" "clamscan"
    "freshclam" "chkrootkit" "trivy" "nmcli" "nmap" "docker" "podman"
    "apt-get" "dnf" "rpm" "dpkg-query" "lynis" "needrestart" "debsums"
    "python3" "pwck" "grpck" "who" "w" "last" "lastb" "lastlog" "lastlog2"
    "curl" "wget" "cryptsetup" "unhide" "lsusb" "lsblk" "lspci" "bluetoothctl" "mokutil"
)

# Sections in run order: "id|title|function". Ids are used by --only / --skip.
SECTIONS=(
    "history|Shell History: Sensitive Data in Command Lines|section_shell_history"
    "keys|SSH Keys, Minikube & TLS/SSH Certificates|section_keys_and_certs"
    "sshd|SSH Daemon Configuration, Ciphers & Security Directives|section_sshd"
    "network|Network Security: Firewall, Listening Ports, Databases & VPN|section_network"
    "malware|Antivirus & Rootkit Scanners (ClamAV / chkrootkit)|section_malware_scanners"
    "files|Filesystem Permissions, Integrity & Temporary Directories|section_filesystem"
    "auditors|External Auditors (Trivy / Lynis)|section_external_auditors"
    "logins|User Logins, Sessions, Boots & Authentication Logs|section_logins"
    "resources|System Resources & Optimization Opportunities|section_resources"
    "accounts|User Accounts, Groups, Passwords, Sudoers & PAM|section_accounts"
    "packages|Package Repositories, Kernel & Recommended Security Packages|section_packages"
    "updates|Pending Package Updates & Automatic Security Updates|section_updates"
    "processes|Running Processes: Malware Indicators & Resource Usage|section_processes"
    "shellrc|Shell Config Files (.bashrc, .zshrc), Safety Aliases & \$PATH|section_shell_configs"
    "suid|SUID / SGID Executables & World-Writable System Files|section_suid"
    "persistence|Persistence: Cron Jobs, Systemd Timers & at Jobs|section_persistence"
    "authkeys|SSH Authorized Keys (All Users)|section_authorized_keys"
    "containers|Docker & Container Security|section_containers"
    "boot|Bootloader, Secure Boot & Kernel Hardening (sysctl)|section_boot_and_kernel"
    "dns|DNS Resolvers, Encrypted DNS (DoH/DoT) & /etc/hosts|section_dns"
    "hardware|Hardware Devices, Wi-Fi Security & Local Network Hosts|section_hardware_and_lan"
    "logging|Logging & Auditing Services (journald / rsyslog / auditd)|section_logging"
    "crypto|Disk Encryption (LUKS) & MAC Framework (SELinux / AppArmor)|section_encryption_and_mac"
    "rootkit|Behavioral Rootkit Indicators (hidden processes, preload hooks, modules)|section_rootkit_indicators"
)

declare -A TOOL_FOUND=()
# Packages installed BY THIS RUN (reported at the end, never touched otherwise)
declare -A AUDIT_INSTALLED_PKGS=()
PKG_MGR=""      # apt | dnf | empty
WORK_DIR=""     # private scratch dir, removed on exit
REPORT_FILE=""
TEE_PID=""

# ==============================================================================
# Output & scoring
# ==============================================================================
PASSED_COUNT=0
WARNING_COUNT=0
CRITICAL_COUNT=0
TOTAL_CHECKS=0
SECTION_NO=0
SECTION_TOTAL=0

section()    { SECTION_NO=$((SECTION_NO + 1)); echo -e "\n${BLUE}[${SECTION_NO}/${SECTION_TOTAL}] $1${NC}"; }
subsection() { echo -e "\n${YELLOW}--- $1 ---${NC}"; }
step()       { echo -e "\n${CYAN}$1${NC}"; }

log_pass() {
    PASSED_COUNT=$((PASSED_COUNT + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    echo -e "${GREEN}[OK] $1${NC}"
}

log_warn() {
    WARNING_COUNT=$((WARNING_COUNT + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    echo -e "${YELLOW}[WARN] $1${NC}"
}

log_crit() {
    CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    echo -e "${RED}CRITICAL: $1${NC}"
}

# Informational lines: shown in the report but NOT counted as pass/warn/crit
log_info() { echo -e "${CYAN}[INFO] $1${NC}"; }
log_skip() { echo -e "${YELLOW}[SKIP] $1${NC}"; }

# ==============================================================================
# Generic helpers
# ==============================================================================

# have TOOL: available on this system (pre-flight result if the tool was checked there)
have() {
    if [[ -n "${TOOL_FOUND[$1]+set}" ]]; then
        [[ "${TOOL_FOUND[$1]}" -eq 1 ]]
    else
        command -v "$1" &>/dev/null
    fi
}

# matches REGEX TEXT: extended-regex match on captured text (safe under pipefail, see top)
matches() { grep -qE -- "$1" <<< "$2"; }

unit_active() { systemctl is-active --quiet "$1" 2>/dev/null; }
unit_exists() { [[ -n "$(systemctl list-unit-files --no-legend "$1" 2>/dev/null)" ]]; }

file_mode() { stat -L -c %a "$1" 2>/dev/null; }
# mode_has MODE BITS: any of the octal BITS is set in MODE (mode_has 755 022 -> group/other writable?)
mode_has() { [[ "$1" =~ ^[0-7]+$ ]] && (( 8#$1 & 8#$2 )); }
human_size() { numfmt --to=iec-i --suffix=B "$1" 2>/dev/null || echo "$(( $1 / 1048576 ))MiB"; }

# Home directory of the user who ran sudo (empty when started as root directly)
invoking_home() { [[ -n "${SUDO_USER:-}" ]] && getent passwd "$SUDO_USER" | cut -d: -f6; }

# Account lists as "name:uid:home:shell" lines (passwd fields never contain ':')
all_accounts()   { awk -F: '{print $1":"$3":"$6":"$7}' /etc/passwd; }
# root and regular users (UID >= 1000, without 'nobody')
human_accounts() { awk -F: '$3 == 0 || ($3 >= 1000 && $3 != 65534) {print $1":"$3":"$6":"$7}' /etc/passwd; }
has_login_shell() { [[ ! "$1" =~ (nologin|false|sync|halt|shutdown|null)$ ]]; }
user_is_admin() {
    local groups_re=' (sudo|wheel|admin) '
    [[ " $(id -nG "$1" 2>/dev/null) " =~ $groups_re ]]
}

root_on_luks() {
    local src
    src=$(findmnt -n -o SOURCE / 2>/dev/null)
    [[ -n "$src" ]] && matches '^crypt$' "$(lsblk -s -n -o TYPE "$src" 2>/dev/null)"
}

# fetch_url URL DEST TIMEOUT_SEC: download with curl or wget into DEST (atomic)
fetch_url() {
    local url=$1 dest=$2 timeout=$3
    if have curl; then
        curl -sL --max-time "$timeout" -o "${dest}.tmp" "$url" 2>/dev/null
    else
        wget -q --timeout="$timeout" -O "${dest}.tmp" "$url" 2>/dev/null
    fi
    if [[ $? -eq 0 && -s "${dest}.tmp" ]]; then
        mv -f "${dest}.tmp" "$dest"
    else
        rm -f "${dest}.tmp"
        return 1
    fi
}

# remote_size URL: Content-Length reported by the server (empty if unknown)
remote_size() {
    if have curl; then
        curl -sIL --max-time 20 "$1" 2>/dev/null | grep -i '^Content-Length:' | tail -n 1 | tr -dc '0-9'
    else
        wget --spider -S --timeout=20 "$1" 2>&1 | grep -i 'Content-Length' | tail -n 1 | tr -dc '0-9'
    fi
}

# ==============================================================================
# Package manager layer (apt / dnf)
# ==============================================================================
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

restart_service() {
    local service="$1"
    local reason="${2:-auto-remediation}"

    if [[ "$AUTO_RESTART_SERVICES" != true ]]; then
        log_skip "Service restart skipped for '${service}' (use --restart-services)."
        return 0
    fi

    # Never restart units that would tear down the running desktop session / network
    case "$service" in
        gdm*|lightdm*|sddm*|display-manager*|systemd-logind*|dbus*|user@*|user-runtime-dir@*|getty@*|NetworkManager*|wpa_supplicant*)
            log_skip "'${service}' not restarted automatically (would disrupt the active session) - reboot or restart it manually."
            return 0
            ;;
    esac

    echo -n "Restarting service '${service}' (${reason})... "
    if systemctl restart "$service" 2>/dev/null; then
        log_pass "Service '${service}' restarted successfully."
    else
        log_warn "Failed to restart service '${service}'."
        return 1
    fi
}

# ==============================================================================
# Run setup: arguments, root check, report, pre-flight
# ==============================================================================
usage() { awk 'NR > 2 { if (/^# =+$/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"; }

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
    local id ids known=","
    local entry
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
            --report-dir|--only|--skip)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == -* ]]; then
                    echo "Error: $1 requires a value." >&2
                    exit 2
                fi
                case "$1" in
                    --report-dir) REPORT_DIR="$2" ;;
                    --only)       ONLY_SECTIONS="$2" ;;
                    --skip)       SKIP_SECTIONS="$2" ;;
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
        echo -e "${RED}Error: This script must be run as a privileged user (root or via sudo).${NC}"
        exit 1
    fi
}

setup_report() {
    if ! mkdir -p "$REPORT_DIR" 2>/dev/null; then
        echo -e "${RED}Error: cannot create report directory '${REPORT_DIR}'.${NC}" >&2
        exit 1
    fi
    REPORT_FILE="$REPORT_DIR/audit-report-$(date +%Y-%m-%d_%H-%M-%S).md"
    : > "$REPORT_FILE" && chmod 600 "$REPORT_FILE"
    # Let the invoking user read the report without sudo
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        chown "$SUDO_USER": "$REPORT_FILE" 2>/dev/null
    fi

    # Private scratch directory: the ONLY place this script creates temp files
    WORK_DIR="$(mktemp -d /tmp/system-audit.XXXXXX)"

    # Everything printed from now on also goes to the report (without colors).
    # tee/sed ignore Ctrl-C/TERM (they stop at end of input), so an interrupted run still
    # gets its last lines and the "interrupted" note into the report.
    exec > >(trap '' INT TERM; tee >(trap '' INT TERM; sed -u -r 's/\x1B\[[0-9;]*[mK]//g' > "$REPORT_FILE")) 2>&1
    TEE_PID=$!
    trap on_exit EXIT
    trap 'echo -e "\n${RED}Audit interrupted - the report contains the sections completed so far.${NC}"; exit 130' INT TERM
}

on_exit() {
    [[ -n "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
    # Close our end of the report pipe and let tee finish writing before the shell returns
    exec >&- 2>&-
    [[ -n "$TEE_PID" ]] && wait "$TEE_PID" 2>/dev/null
}

print_banner() {
    echo -e "${CYAN}=====================================================${NC}"
    echo -e "${CYAN}=== Starting System Security & Optimization Audit ===${NC}"
    echo -e "${CYAN}=====================================================${NC}"
    echo -e "Audit Version    : ${CYAN}${VERSION}${NC}"
    echo -e "Audit Started At : ${CYAN}${AUDIT_START_TIME_STR}${NC}"
    [[ -n "$ONLY_SECTIONS" ]] && echo -e "Sections (--only): ${CYAN}${ONLY_SECTIONS}${NC}"
    [[ -n "$SKIP_SECTIONS" ]] && echo -e "Skipped (--skip) : ${CYAN}${SKIP_SECTIONS}${NC}"
}

install_tool_package() {
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
    echo -e "${YELLOW}=== Pre-Flight Security Tools & Dependency Check ===${NC}"
    local tool found=0 missing=() scanner_pkgs=()

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
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "  [${YELLOW}!${NC}] Not installed: ${YELLOW}${missing[*]}${NC}"
    fi

    if [[ ${#scanner_pkgs[@]} -gt 0 ]]; then
        if [[ "$INSTALL_MISSING_PKGS" == true && -n "$PKG_MGR" ]]; then
            echo -e "\n${YELLOW}=== Auto-Installing Missing Security Tools ===${NC}"
            local pkg
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
            echo -e "\n${YELLOW}Recommended Security Tools Installation Tip:${NC}"
            case "$PKG_MGR" in
                apt) echo -e "  Debian/Ubuntu: ${CYAN}sudo apt install ${scanner_pkgs[*]}${NC}" ;;
                dnf) echo -e "  Fedora/RHEL:   ${CYAN}sudo dnf install ${scanner_pkgs[*]}${NC}" ;;
            esac
            echo -e "  Tip: run with --install to auto-install missing tools."
        fi
    fi
    if ! have trivy; then
        echo -e "${YELLOW}Note:${NC} trivy is not in the Debian repositories (apt cannot install it). Optional - see https://trivy.dev/latest/getting-started/installation/"
    fi
    echo ""
}

# ==============================================================================
# Opt-in changes: --fix, --update-db
# ==============================================================================

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

    if [[ "$fixes" -gt 0 ]]; then
        echo -e "  ${GREEN}[OK] Applied ${fixes} runbook-based automatic permission/system fix(es).${NC}\n"
    fi
}

apply_fixes() {
    echo -e "${YELLOW}=== Running in Auto-Fix Mode (--fix enabled) ===${NC}"
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
    echo -e "${GREEN}[OK] Auto-fix completed: Permissions, safety aliases & runbook fixes applied.${NC}\n"
}

update_security_databases() {
    echo -e "${YELLOW}--- Updating Security & Audit Tool Databases ---${NC}"

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
    echo ""
}

# ==============================================================================
# Sections
# ==============================================================================

# --- Shell history -------------------------------------------------------------
clean_history_file() {
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
    local regex user uid home shell f n hits=0
    local files=()
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
        hits=$(( hits + ${n:-0} ))
    done
    if [[ "$hits" -gt 0 ]]; then
        log_warn "${hits} shell-history line(s) contain keywords such as password/token/secret (review them; --clean-history removes them, backup is kept)."
    else
        log_pass "No sensitive keywords found in shell history files (${#files[@]} file(s) checked)."
    fi
}

# --- SSH keys, Minikube & certificates ------------------------------------------
section_keys_and_certs() {
    local now user uid home shell
    now=$(date +%s)

    subsection "Minikube Certificate Permissions"
    local minikube_found=0 loose
    while IFS=: read -r user uid home shell; do
        [[ -d "$home/.minikube" ]] || continue
        minikube_found=1
        loose=$(find "$home/.minikube" -name "*.pem" -perm /077 2>/dev/null)
        if [[ -n "$loose" ]]; then
            log_warn "User '${user}': insecure Minikube PEM permissions (fix: --fix):\n${loose}"
        else
            log_pass "User '${user}': Minikube certificate permissions are secure."
        fi
    done < <(human_accounts)
    [[ "$minikube_found" -eq 0 ]] && echo "No Minikube profiles found."

    subsection "SSH Private Keys: Passphrase Protection & Age (Host & User Keys)"
    # Entries are "owner:path"; host keys use the owner "host" and are never passphrase-protected
    local keys=() key entry owner
    local -A seen=()
    while read -r key; do
        keys+=("host:${key}")
    done < <(find /etc/ssh -maxdepth 1 -type f -name "ssh_host_*_key" 2>/dev/null)
    while IFS=: read -r user uid home shell; do
        [[ -d "$home/.ssh" ]] || continue
        while read -r key; do
            [[ -n "${seen[$key]:-}" ]] && continue
            seen[$key]=1
            grep -q "PRIVATE KEY" "$key" 2>/dev/null && keys+=("${user}:${key}")
        done < <(find "$home/.ssh" -maxdepth 2 -type f ! -name "*.pub" ! -name "known_hosts*" ! -name "authorized_keys*" ! -name "config" 2>/dev/null)
    done < <(all_accounts)

    local user_keys=0 unprotected=0 old_keys=0 mtime age_days created
    for entry in "${keys[@]}"; do
        owner="${entry%%:*}"
        key="${entry#*:}"
        mtime=$(stat -c %Y "$key" 2>/dev/null) || continue
        age_days=$(( (now - mtime) / 86400 ))
        created=$(date -d "@${mtime}" +%F)

        if [[ "$owner" == "host" ]]; then
            echo -e "  - Host Key: ${CYAN}${key}${NC} | Created/Modified: ${created} (${age_days} days old)"
        else
            user_keys=$((user_keys + 1))
            if have ssh-keygen && ssh-keygen -y -P "" -f "$key" &>/dev/null; then
                unprotected=$((unprotected + 1))
                log_crit "UNPROTECTED SSH KEY: User ${owner} -> ${key} (No passphrase set!)"
            else
                echo -e "  - ${GREEN}[OK] Protected SSH Key:${NC} User ${CYAN}${owner}${NC} -> ${key} | Created/Modified: ${created} (${age_days} days old)"
            fi
        fi

        if [[ "$age_days" -ge 365 ]]; then
            old_keys=$((old_keys + 1))
            log_warn "SSH Key '${key}' is ${age_days} days old (created ${created}). Recommend key rotation."
        fi
    done

    if [[ ${#keys[@]} -eq 0 ]]; then
        log_pass "No SSH private keys found on the system."
    else
        if [[ "$user_keys" -gt 0 && "$unprotected" -eq 0 ]]; then
            log_pass "All discovered user SSH private keys (${user_keys}) are protected with passphrases."
        fi
        if [[ "$old_keys" -eq 0 ]]; then
            log_pass "All ${#keys[@]} SSH private key(s) are less than 1 year old."
        fi
    fi

    subsection "SSL/TLS Certificate Expiration (/etc/ssl, /etc/letsencrypt, /etc/pki, ~/.minikube)"
    if ! have openssl; then
        echo -e "${YELLOW}openssl command not available for certificate expiration inspection.${NC}"
    else
        local certs=() dir cert enddate end_sec days_left expired=0 expiring=0 valid=0
        for dir in /etc/ssl/certs /etc/pki; do
            [[ -d "$dir" ]] || continue
            while read -r cert; do certs+=("$cert"); done < <(find "$dir" -type f \( -name "*.crt" -o -name "*.pem" -o -name "*.cer" \) 2>/dev/null | head -n 30)
        done
        # Let's Encrypt 'live' entries are symlinks into ../archive
        while read -r cert; do certs+=("$cert"); done < <(find -L /etc/letsencrypt/live -type f -name "cert.pem" 2>/dev/null)
        while IFS=: read -r user uid home shell; do
            [[ -d "$home/.minikube" ]] || continue
            while read -r cert; do certs+=("$cert"); done < <(find "$home/.minikube" -type f \( -name "*.crt" -o -name "*.pem" \) 2>/dev/null | head -n 30)
        done < <(human_accounts)

        for cert in "${certs[@]}"; do
            enddate=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
            [[ -n "$enddate" ]] || continue
            end_sec=$(date -d "$enddate" +%s 2>/dev/null) || continue
            days_left=$(( (end_sec - now) / 86400 ))
            if [[ "$days_left" -lt 0 ]]; then
                log_crit "Certificate '${cert}' EXPIRED $(( -days_left )) days ago (Expired on ${enddate})!"
                expired=$((expired + 1))
            elif [[ "$days_left" -le 30 ]]; then
                log_warn "Certificate '${cert}' EXPIRING SOON in ${days_left} days (Expires on ${enddate})."
                expiring=$((expiring + 1))
            else
                valid=$((valid + 1))
            fi
        done
        if [[ "$expired" -eq 0 && "$expiring" -eq 0 ]]; then
            log_pass "All scanned SSL/TLS certificates (${valid}) are valid and not expiring within 30 days."
        fi
    fi

    subsection "OpenSSH Certificate Expiration (*-cert.pub)"
    local ssh_certs=() scert validity
    while read -r scert; do ssh_certs+=("$scert"); done < <(find /etc/ssh /home /root -name "*-cert.pub" -type f 2>/dev/null)
    if [[ ${#ssh_certs[@]} -gt 0 ]]; then
        for scert in "${ssh_certs[@]}"; do
            validity=$(ssh-keygen -L -f "$scert" 2>/dev/null | grep -i "Valid:")
            echo -e "  - OpenSSH Cert ${CYAN}${scert}${NC}: ${validity:-Checked}"
        done
        log_pass "Audited ${#ssh_certs[@]} OpenSSH certificate(s)."
    else
        echo "No OpenSSH certificate files (*-cert.pub) found."
    fi
}

# --- SSH daemon -----------------------------------------------------------------
SSHD_EFFECTIVE=""   # `sshd -T` output (effective configuration), if available

# sshd_param NAME DEFAULT: effective value, else the first match in the config files
# (drop-ins first: Debian includes sshd_config.d/*.conf at the top and the first value wins)
sshd_param() {
    local name="$1" default="$2" val=""
    if [[ -n "$SSHD_EFFECTIVE" ]]; then
        val=$(awk -v p="$name" 'tolower($1) == p {print $2; exit}' <<< "$SSHD_EFFECTIVE")
    fi
    if [[ -z "$val" ]]; then
        val=$(cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \
              | awk -v p="$name" '!/^[[:space:]]*#/ && tolower($1) == p {print $2; exit}')
    fi
    echo "${val:-$default}"
}

section_sshd() {
    if [[ ! -f /etc/ssh/sshd_config && ! -d /etc/ssh/sshd_config.d ]]; then
        echo -e "  ${YELLOW}OpenSSH Daemon config not found (/etc/ssh/sshd_config missing). SSH daemon may not be installed.${NC}"
        return 0
    fi

    subsection "SSH Daemon Effective Configuration & Authentication Directives"
    have sshd && SSHD_EFFECTIVE=$(sshd -T 2>/dev/null)

    local ssh_port
    ssh_port=$(sshd_param port 22)
    echo -e "  SSH Listening Port          : ${CYAN}${ssh_port}${NC}"
    if [[ "$ssh_port" == "22" ]]; then
        echo -e "  ${YELLOW}Tip: SSH daemon is running on standard port 22. Changing to a non-standard port reduces automated bot brute-force noise.${NC}"
    else
        log_pass "SSH daemon running on custom non-standard port (${ssh_port})."
    fi

    local root_login
    root_login=$(sshd_param permitrootlogin prohibit-password)
    echo -e "  PermitRootLogin             : ${CYAN}${root_login}${NC}"
    case "$root_login" in
        yes) log_crit "PermitRootLogin is enabled ('yes')! Direct root SSH login allows brute-force attacks against the root account! Recommended: 'no' or 'prohibit-password'." ;;
        prohibit-password|without-password) log_pass "PermitRootLogin set to '${root_login}' (Root SSH login allowed via SSH key only)." ;;
        *) log_pass "PermitRootLogin set to '${root_login}' (Direct root SSH login disabled)." ;;
    esac

    local pass_auth
    pass_auth=$(sshd_param passwordauthentication yes)
    echo -e "  PasswordAuthentication      : ${CYAN}${pass_auth}${NC}"
    if [[ "$pass_auth" == "yes" ]]; then
        log_warn "PasswordAuthentication is enabled ('yes'). Password brute-force attacks are possible. Recommended: Disable password authentication in favor of SSH Keys ('PasswordAuthentication no')."
    else
        log_pass "PasswordAuthentication is disabled (Enforced SSH key authentication)."
    fi

    local empty_pass
    empty_pass=$(sshd_param permitemptypasswords no)
    echo -e "  PermitEmptyPasswords        : ${CYAN}${empty_pass}${NC}"
    if [[ "$empty_pass" == "yes" ]]; then
        log_crit "PermitEmptyPasswords is enabled ('yes')! Accounts with blank passwords can log in via SSH!"
    else
        log_pass "PermitEmptyPasswords is set to 'no'."
    fi

    local pubkey_auth
    pubkey_auth=$(sshd_param pubkeyauthentication yes)
    echo -e "  PubkeyAuthentication        : ${CYAN}${pubkey_auth}${NC}"
    if [[ "$pubkey_auth" == "no" ]]; then
        log_warn "PubkeyAuthentication is disabled! SSH key authentication is turned off."
    else
        log_pass "PubkeyAuthentication is enabled."
    fi

    local x11_fwd
    x11_fwd=$(sshd_param x11forwarding no)
    echo -e "  X11Forwarding               : ${CYAN}${x11_fwd}${NC}"
    if [[ "$x11_fwd" == "yes" ]]; then
        log_warn "X11Forwarding is enabled ('yes'). X11 display redirection increases attack surface unless required."
    else
        log_pass "X11Forwarding is disabled."
    fi

    local max_tries
    max_tries=$(sshd_param maxauthtries 6)
    echo -e "  MaxAuthTries                : ${CYAN}${max_tries}${NC}"
    if [[ "$max_tries" =~ ^[0-9]+$ && "$max_tries" -gt 4 ]]; then
        log_warn "MaxAuthTries is set to ${max_tries} (Recommended: <= 4 to mitigate brute-force attempts)."
    else
        log_pass "MaxAuthTries configuration verified (${max_tries})."
    fi

    subsection "SSH Cryptographic Algorithms Audit (Ciphers, MACs, KEX)"
    local ciphers macs kex weak
    ciphers=$(sshd_param ciphers "")
    macs=$(sshd_param macs "")
    kex=$(sshd_param kexalgorithms "")

    if [[ -n "$ciphers" ]]; then
        echo -e "  Configured Ciphers          : ${CYAN}${ciphers}${NC}"
        weak=$(grep -oEi "3des-cbc|blowfish-cbc|cast128-cbc|aes(128|192|256)-cbc|arcfour[0-9]*|none" <<< "$ciphers" | paste -sd, -)
        if [[ -n "$weak" ]]; then
            log_crit "Weak / Obsolete SSH Ciphers enabled: ${weak}! Recommended: chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com."
        else
            log_pass "No explicitly blacklisted legacy SSH ciphers detected in the effective configuration."
        fi
    fi

    if [[ -n "$macs" ]]; then
        echo -e "  Configured MACs             : ${CYAN}${macs}${NC}"
        weak=$(tr ',' '\n' <<< "$macs" | grep -xEi "hmac-md5(-96)?(-etm@openssh.com)?|hmac-sha1(-96)?|umac-64@openssh.com" | paste -sd, -)
        if [[ -n "$weak" ]]; then
            log_warn "Weak / Obsolete SSH MAC Algorithms enabled: ${weak}! Recommended: hmac-sha2-512-etm@openssh.com, hmac-sha2-256-etm@openssh.com."
        else
            log_pass "SSH MAC Algorithms verified."
        fi
    fi

    if [[ -n "$kex" ]]; then
        echo -e "  Configured KEX Algorithms   : ${CYAN}${kex}${NC}"
        weak=$(grep -oEi "diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1" <<< "$kex" | paste -sd, -)
        if [[ -n "$weak" ]]; then
            log_warn "Weak / Obsolete SSH Key Exchange (KEX) algorithms enabled: ${weak}! Recommended modern KEX: curve25519-sha256 / curve25519-sha256@libssh.org and group16+ SHA-2 variants."
        else
            log_pass "SSH Key Exchange (KEX) algorithms verified."
        fi
    fi
}

# --- Network --------------------------------------------------------------------
audit_firewall() {
    subsection "Firewall Configuration & Active Rule Audit (UFW / firewalld / nftables / iptables)"
    local firewall_active=false

    if have ufw; then
        local ufw_out ufw_default
        ufw_out=$(ufw status verbose 2>/dev/null)
        if [[ "$ufw_out" == *"Status: active"* ]]; then
            firewall_active=true
            ufw_default=$(grep -i -m1 "Default:" <<< "$ufw_out")
            echo -e "  UFW Firewall Status: ${GREEN}ACTIVE${NC} (${ufw_default:-Default rules configured})"
            log_pass "UFW packet filtering firewall is ACTIVE."
        elif [[ -n "$ufw_out" ]]; then
            echo -e "  UFW Firewall Status: ${YELLOW}INACTIVE${NC}"
        fi
    fi

    if have firewall-cmd && [[ "$(firewall-cmd --state 2>/dev/null)" == "running" ]]; then
        firewall_active=true
        local active_zone
        active_zone=$(firewall-cmd --get-active-zones 2>/dev/null | head -n 1)
        echo -e "  firewalld Status: ${GREEN}RUNNING${NC} (Active Zone: ${active_zone:-default})"
        log_pass "firewalld packet filtering firewall is RUNNING."
    fi

    if have nft; then
        local nft_rules
        nft_rules=$(nft list ruleset 2>/dev/null)
        if [[ "$nft_rules" == *"table "* ]]; then
            firewall_active=true
            echo -e "  nftables Status: ${GREEN}ACTIVE${NC} ($(grep -c "chain " <<< "$nft_rules") active filtering chain(s))"
            log_pass "nftables packet filtering ruleset verified."
        fi
    fi

    if have iptables; then
        local ipt_rules input_pol rule_count
        ipt_rules=$(iptables -L -n -v 2>/dev/null)
        if [[ -n "$ipt_rules" ]]; then
            # "Chain INPUT (policy DROP 0 packets, 0 bytes)"
            input_pol=$(grep -m1 "^Chain INPUT" <<< "$ipt_rules" | grep -oE 'policy [A-Z]+' | awk '{print $2}')
            rule_count=$(grep -cE '^[[:space:]]*[0-9]+' <<< "$ipt_rules")
            echo -e "  iptables IPv4 INPUT Policy : ${CYAN}${input_pol:-UNKNOWN}${NC} (${rule_count} active filtering rules)"
            if [[ "$input_pol" == "DROP" || "$input_pol" == "REJECT" ]]; then
                firewall_active=true
            elif [[ "$rule_count" -gt 0 ]]; then
                # Rules exist but the default INPUT policy is ACCEPT: configured, not necessarily protective
                firewall_active=true
                log_warn "iptables has ${rule_count} rule(s), but INPUT policy is ${input_pol:-UNKNOWN}; verify that the rules actually restrict unwanted inbound traffic."
            fi
        fi
    fi

    if [[ "$firewall_active" == true ]]; then
        log_pass "Active network packet filtering firewall verified."
    else
        log_crit "NO ACTIVE FIREWALL FILTERING: System has no active iptables/nftables/ufw filtering rules! All incoming network connections are unfiltered!"
    fi
}

audit_listening_sockets() {
    subsection "Open Listening TCP/UDP Ports & Associated Processes (ss -tulpn)"
    have ss || return 0
    local ss_output
    ss_output=$(ss -tulpn 2>/dev/null)
    if [[ -z "$ss_output" ]]; then
        log_pass "No active listening TCP/UDP sockets found."
        return 0
    fi

    # Names and IPs of virtual bridges (libvirt virbr*, docker*, br-*): reachable only from VMs/containers
    local bridge_ifaces bridge_ips bi
    bridge_ifaces=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(virbr|docker|br-|lxcbr|podman|cni)')
    bridge_ips=$(for bi in $bridge_ifaces; do ip -o addr show dev "$bi" 2>/dev/null | awk '{split($4, a, "/"); print a[1]}'; done)

    local public_count=0 local_count=0 bridge_count=0 suspicious=()
    local netid local_addr proc port addr scope proc_name
    echo -e "  ${CYAN}Active Listening Network Sockets:${NC}"
    # Netid State Recv-Q Send-Q Local:Port Peer:Port Process
    while read -r netid _ _ _ local_addr _ proc; do
        [[ -z "$local_addr" ]] && continue
        port="${local_addr##*:}"
        addr="${local_addr%:*}"

        proc_name="[Unknown/Root]"
        [[ "$proc" =~ users:\(\(\"([^\"]+)\" ]] && proc_name="${BASH_REMATCH[1]}"
        [[ "$proc" =~ pid=([0-9]+) ]] && proc_name+=" (PID: ${BASH_REMATCH[1]})"

        if [[ "$addr" =~ ^127\. || "$addr" == "[::1]" ]]; then
            scope="Localhost"
            local_count=$((local_count + 1))
        elif [[ "$addr" == *%* || "$addr" =~ ^\[fe80: ]] && [[ "$port" =~ ^(546|68)$ ]]; then
            # DHCP client bound to a link-local address: not a reachable service
            scope="Link-local"
            local_count=$((local_count + 1))
        elif { [[ "$addr" == *%* ]] && grep -qxF "${addr##*%}" <<< "$bridge_ifaces"; } \
             || grep -qxF "$(tr -d '[]' <<< "${addr%%\%*}")" <<< "$bridge_ips"; then
            scope="VM-bridge"
            bridge_count=$((bridge_count + 1))
        else
            scope="Public"
            public_count=$((public_count + 1))
            case "$port" in
                21) suspicious+=("FTP (Port 21, Unencrypted cleartext credentials)") ;;
                23) suspicious+=("Telnet (Port 23, Unencrypted cleartext shell access)") ;;
                25) suspicious+=("SMTP (Port 25, Plaintext mail relay)") ;;
                69) suspicious+=("TFTP (Port 69, Unauthenticated file transfer)") ;;
                80) echo -e "    - HTTP (Port 80): Plaintext web service active" ;;
                161|162) suspicious+=("SNMP (Port ${port}, Unencrypted network management)") ;;
                512|513|514) suspicious+=("Legacy Remote Shell R-Services (Port ${port})") ;;
                3306) suspicious+=("MySQL Database (Port 3306 exposed on public interface!)") ;;
                5432) suspicious+=("PostgreSQL Database (Port 5432 exposed on public interface!)") ;;
                6379) suspicious+=("Redis Cache (Port 6379 exposed on public interface!)") ;;
                27017) suspicious+=("MongoDB (Port 27017 exposed on public interface!)") ;;
                11211) suspicious+=("Memcached (Port 11211 exposed on public interface!)") ;;
                9200) suspicious+=("Elasticsearch (Port 9200 exposed on public interface!)") ;;
            esac
        fi
        printf "    - %-5s | %-20s | Port %-5s | Scope: %-10s | Process: %s\n" "$netid" "$addr" "$port" "$scope" "$proc_name"
    done < <(tail -n +2 <<< "$ss_output")

    log_pass "Listening Sockets Audit Summary: ${public_count} public socket(s), ${bridge_count} VM/container-bridge-only socket(s), ${local_count} localhost-only socket(s)."
    if [[ ${#suspicious[@]} -gt 0 ]]; then
        log_crit "RISKY / UNENCRYPTED PUBLIC LISTENING SERVICES DETECTED:\n$(printf '%s\n' "${suspicious[@]}")"
    fi

    if matches ':5355[[:space:]].*systemd-resolve' "$ss_output"; then
        log_warn "LLMNR (UDP/TCP 5355) is active in systemd-resolved. Disable with LLMNR=no in /etc/systemd/resolved.conf.d/ unless needed."
    fi
    if matches ':5353[[:space:]].*avahi' "$ss_output"; then
        log_warn "avahi-daemon (mDNS, UDP 5353) is listening. Disable avahi-daemon if you do not need network printers / Chromecast / .local discovery."
    fi
    if matches ':(500|4500)[[:space:]].*charon' "$ss_output"; then
        log_info "strongSwan (charon) listens on IKE ports 500/4500. Expected if you use IPsec/IKEv2; otherwise: systemctl disable --now strongswan-starter strongswan"
    fi
}

audit_established_connections() {
    subsection "Active Established Outbound Network Connections"
    have ss || return 0
    local conns
    conns=$(ss -tunp state established 2>/dev/null | grep -v '127\.0\.0\.1' | grep -v '::1')
    if [[ $(wc -l <<< "$conns") -gt 1 ]]; then
        sed 's/^/  /' <<< "$conns"
        log_pass "Audited $(( $(wc -l <<< "$conns") - 1 )) active established outbound network connection(s)."
    else
        log_pass "No active established outbound connections to external hosts."
    fi
}

audit_vpn() {
    subsection "Active VPN, Mesh & Tunneling Interfaces"
    local vpn_ifaces
    vpn_ifaces=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(tun[0-9]|tap[0-9]|wg[0-9]|tailscale|zerotier|zt)' | paste -sd' ' -)
    if [[ -n "$vpn_ifaces" ]]; then
        echo -e "  Active VPN / Mesh interfaces detected: ${CYAN}${vpn_ifaces}${NC}"
        log_pass "VPN/Mesh network interface(s) verified: ${vpn_ifaces}"
    else
        echo -e "  No active VPN/Mesh interfaces (WireGuard, OpenVPN, Tailscale, ZeroTier) detected."
    fi

    local vpn_files=() vfile v_octal
    while read -r vfile; do vpn_files+=("$vfile"); done < <(find /etc/wireguard /etc/openvpn -type f 2>/dev/null)
    [[ ${#vpn_files[@]} -gt 0 ]] || return 0

    step "Auditing VPN Configuration File Permissions:"
    for vfile in "${vpn_files[@]}"; do
        v_octal=$(file_mode "$vfile")
        if [[ "$(head -c 2 "$vfile" 2>/dev/null)" == "#!" ]]; then
            # Hook scripts (e.g. openvpn update-resolv-conf) are code, not secrets:
            # they must be executable by the owner and not writable by group/others
            if mode_has "$v_octal" 100 && ! mode_has "$v_octal" 022; then
                log_pass "${vfile}: VPN hook script permissions OK (${v_octal})"
            else
                log_warn "${vfile}: VPN hook script has mode ${v_octal} (not executable or writable by others). Expected: 755"
            fi
        elif [[ "$v_octal" =~ ^(600|400|640)$ ]]; then
            log_pass "${vfile}: Secure permissions (${v_octal})"
        else
            log_warn "${vfile}: Loose permissions (${v_octal}). Recommended: 600"
        fi
    done
}

# Local database services that accept logins without a password
audit_databases() {
    subsection "Database Unauthenticated & Passwordless Access Audit"
    local listen detected=0 unprotected=0
    listen=$(ss -tuln 2>/dev/null)

    if have mysql || have mariadb || matches ":3306[[:space:]]" "$listen"; then
        detected=$((detected + 1))
        echo -e "${CYAN}Testing MySQL / MariaDB Passwordless Access...${NC}"
        local mysql_cmd
        mysql_cmd=$(command -v mysql || command -v mariadb)
        if [[ -z "$mysql_cmd" ]]; then
            log_info "MySQL/MariaDB port 3306 is open, but no client is installed to test it."
        elif "$mysql_cmd" -h 127.0.0.1 -u root --password="" -e "SELECT 1;" &>/dev/null; then
            log_crit "UNAUTHENTICATED ACCESS: MySQL/MariaDB allows passwordless 'root' login over TCP (127.0.0.1)!"
            unprotected=$((unprotected + 1))
        elif "$mysql_cmd" -h 127.0.0.1 -u anonymous --password="" -e "SELECT 1;" &>/dev/null; then
            log_crit "UNAUTHENTICATED ACCESS: MySQL/MariaDB allows passwordless 'anonymous' user login over TCP!"
            unprotected=$((unprotected + 1))
        else
            log_pass "MySQL/MariaDB requires password authentication over TCP."
        fi
    fi

    if have psql || matches ":5432[[:space:]]" "$listen"; then
        detected=$((detected + 1))
        echo -e "${CYAN}Testing PostgreSQL Passwordless & Trust Authentication...${NC}"
        if have psql && PGPASSWORD="" psql -h 127.0.0.1 -U postgres -c "SELECT 1;" &>/dev/null; then
            log_crit "UNAUTHENTICATED ACCESS: PostgreSQL allows passwordless 'postgres' login over TCP (127.0.0.1)!"
            unprotected=$((unprotected + 1))
        else
            log_pass "PostgreSQL requires password authentication over TCP."
        fi
        local hba trust_rules
        while read -r hba; do
            trust_rules=$(grep -Ei "^[[:space:]]*(host|local)[[:space:]]+.*trust" "$hba" 2>/dev/null)
            [[ -n "$trust_rules" ]] && log_warn "Dangerous 'trust' authentication method found in ${hba}:\n$trust_rules"
        done < <(find /etc/postgresql /var/lib/pgsql -name "pg_hba.conf" 2>/dev/null)
    fi

    if have redis-cli || matches ":6379[[:space:]]" "$listen"; then
        detected=$((detected + 1))
        echo -e "${CYAN}Testing Redis Passwordless Access...${NC}"
        if have redis-cli && [[ "$(redis-cli -h 127.0.0.1 -p 6379 PING 2>/dev/null)" == "PONG" ]]; then
            log_crit "UNAUTHENTICATED ACCESS: Redis server (127.0.0.1:6379) responds to PING without a password!"
            unprotected=$((unprotected + 1))
        else
            log_pass "Redis server requires authentication (requirepass configured)."
        fi
    fi

    if have mongosh || have mongo || matches ":27017[[:space:]]" "$listen"; then
        detected=$((detected + 1))
        echo -e "${CYAN}Testing MongoDB Passwordless Access...${NC}"
        local mongo_cmd mongo_out=""
        mongo_cmd=$(command -v mongosh || command -v mongo)
        [[ -n "$mongo_cmd" ]] && mongo_out=$("$mongo_cmd" --host 127.0.0.1 --port 27017 --eval "db.adminCommand('ping')" --quiet 2>/dev/null)
        if [[ "$mongo_out" == *ok* ]]; then
            log_crit "UNAUTHENTICATED ACCESS: MongoDB (127.0.0.1:27017) allows administrative commands without authentication!"
            unprotected=$((unprotected + 1))
        else
            log_pass "MongoDB requires authentication for database commands."
        fi
    fi

    if have memcached || matches ":11211[[:space:]]" "$listen"; then
        detected=$((detected + 1))
        echo -e "${CYAN}Testing Memcached Passwordless Access...${NC}"
        if have nc && [[ -n "$(echo "stats" | nc -w 2 127.0.0.1 11211 2>/dev/null | grep -i "STAT")" ]]; then
            log_warn "Memcached (127.0.0.1:11211) is accessible without authentication."
        else
            log_pass "Memcached port 11211 is protected or inactive."
        fi
    fi

    if matches ":9200[[:space:]]" "$listen"; then
        detected=$((detected + 1))
        echo -e "${CYAN}Testing Elasticsearch / OpenSearch Passwordless Access...${NC}"
        local es_out
        es_out=$(curl -s -m 2 http://127.0.0.1:9200/ 2>/dev/null)
        if [[ "$es_out" == *cluster_name* || "$es_out" == *lucene* ]]; then
            log_crit "UNAUTHENTICATED ACCESS: Elasticsearch (127.0.0.1:9200) allows HTTP requests without password authentication!"
            unprotected=$((unprotected + 1))
        else
            log_pass "Elasticsearch requires HTTP authentication."
        fi
    fi

    if [[ "$detected" -eq 0 ]]; then
        log_pass "No active database services (MySQL, PostgreSQL, Redis, MongoDB, Memcached, Elasticsearch) detected."
    elif [[ "$unprotected" -eq 0 ]]; then
        log_pass "All ${detected} detected database service(s) require password authentication."
    fi
}

section_network() {
    audit_firewall
    audit_listening_sockets
    audit_established_connections
    audit_vpn
    audit_databases
}

# --- Antivirus & rootkit scanners -----------------------------------------------
section_malware_scanners() {
    if unit_active clamav-freshclam; then
        log_pass "clamav-freshclam service is active."
    elif unit_exists clamav-freshclam.service; then
        log_warn "clamav-freshclam service is installed but inactive."
        if [[ "$AUTO_FIX" == true && "$AUTO_RESTART_SERVICES" == true ]]; then
            restart_service "clamav-freshclam" "activating antivirus signature update daemon"
        fi
    fi

    if have clamscan; then
        echo "Scanning active system binary paths for malware..."
        local clam_out
        clam_out=$(clamscan -r --exclude-dir="^/sys" --exclude-dir="^/dev" --exclude-dir="^/proc" /bin /sbin /usr/bin /usr/sbin 2>/dev/null | grep -E "Infected|Summary|FOUND")
        if [[ "$clam_out" == *FOUND* || "$clam_out" =~ "Infected files: "[1-9] ]]; then
            log_crit "ClamAV malware threats found!\n$clam_out"
        else
            log_pass "ClamAV scan completed: No threats found."
        fi
    else
        echo -e "${YELLOW}ClamAV (clamscan) not installed.${NC}"
    fi

    if have chkrootkit; then
        echo -e "${CYAN}Running Rootkit Detection (chkrootkit)...${NC}"
        local chk_infected
        # Real INFECTED / VULNERABLE findings only (not "not infected" lines)
        chk_infected=$(chkrootkit -q 2>/dev/null | grep -Ei "INFECTED|VULNERABLE" | grep -v "not infected")
        if [[ -n "$chk_infected" ]]; then
            log_crit "chkrootkit detected potential rootkit signatures:\n$chk_infected"
        else
            log_pass "chkrootkit scan completed: No rootkit signatures detected."
        fi
    elif have rkhunter; then
        echo -e "${CYAN}Running Rootkit Detection (rkhunter)...${NC}"
        rkhunter --check --sk --quiet 2>/dev/null
        log_pass "rkhunter check completed."
    else
        echo -e "${YELLOW}Neither chkrootkit nor rkhunter installed.${NC}"
    fi
}

# --- Filesystem -----------------------------------------------------------------
# check_path_entries KIND TEST ISSUES_VAR ENTRY...: verify "path:mode-regex:owner" entries
# (TEST is -f or -d; missing paths are skipped) and add the problems found to ISSUES_VAR
check_path_entries() {
    local kind="$1" test_op="$2"
    local -n issue_count="$3"
    shift 3
    local item path mode_re owner_want mode owner ok
    for item in "$@"; do
        IFS=":" read -r path mode_re owner_want <<< "$item"
        test "$test_op" "$path" || continue
        mode=$(file_mode "$path")
        owner=$(stat -L -c %U "$path" 2>/dev/null)
        ok=true
        if ! [[ "$mode" =~ $mode_re ]]; then
            log_warn "${kind} '${path}' has non-standard permissions: ${mode} (Recommended: ${mode_re//[\^\$()]/})"
            issue_count=$((issue_count + 1))
            ok=false
        fi
        if [[ -n "$owner" && "$owner" != "$owner_want" ]]; then
            log_crit "${kind} '${path}' is NOT owned by ${owner_want}! Current owner: ${owner}"
            issue_count=$((issue_count + 1))
            ok=false
        fi
        [[ "$ok" == true ]] && echo -e "  - ${path}: ${GREEN}OK${NC} (Mode: ${mode}, Owner: ${owner:-root})"
    done
}

audit_permissions_matrix() {
    subsection "Critical System Files & Directories Permissions Matrix"

    # "path:allowed-mode-regex:owner"
    local critical_files=(
        "/etc/passwd:^644$:root"
        "/etc/group:^644$:root"
        "/etc/shadow:^(600|640)$:root"
        "/etc/gshadow:^(600|640)$:root"
        "/etc/sudoers:^(440|400)$:root"
        "/etc/fstab:^644$:root"
        "/etc/crontab:^(600|644)$:root"
        "/boot/grub/grub.cfg:^(600|700)$:root"
        "/boot/grub2/grub.cfg:^(600|700)$:root"
        "/etc/sysctl.conf:^644$:root"
        "/etc/ssh/sshd_config:^(600|644)$:root"
    )
    local critical_dirs=(
        "/etc:^755$:root"
        "/etc/sudoers.d:^(750|755)$:root"
        "/etc/cron.d:^(755|700)$:root"
        "/etc/cron.daily:^(755|700)$:root"
        "/etc/cron.hourly:^(755|700)$:root"
        "/etc/cron.weekly:^(755|700)$:root"
        "/etc/cron.monthly:^(755|700)$:root"
        "/etc/pam.d:^755$:root"
        "/bin:^755$:root"
        "/sbin:^755$:root"
        "/usr/bin:^755$:root"
        "/usr/sbin:^755$:root"
        "/lib:^755$:root"
        "/lib64:^755$:root"
        "/var/log:^(755|775)$:root"
    )
    local issues=0

    step "1. Critical System File Permissions & Root Ownership Audit:"
    check_path_entries "File" -f issues "${critical_files[@]}"

    step "2. SSH Private Host Keys Permissions Audit (/etc/ssh/ssh_host_*_key):"
    local hk hk_mode found_hk=0
    while read -r hk; do
        found_hk=1
        hk_mode=$(file_mode "$hk")
        if [[ "$hk_mode" =~ ^(600|640)$ ]]; then
            echo -e "  - Host Key ${hk}: ${GREEN}OK${NC} (${hk_mode} $(stat -c %U "$hk" 2>/dev/null))"
        else
            log_crit "SSH Private Host Key '${hk}' has insecure permissions (${hk_mode})! Must be 600 or 640."
            issues=$((issues + 1))
        fi
    done < <(find /etc/ssh -maxdepth 1 -type f -name "ssh_host_*_key" 2>/dev/null)
    [[ "$found_hk" -eq 0 ]] && echo "  No SSH host keys (sshd not installed)."

    step "3. Critical System Directory Permissions Audit:"
    check_path_entries "Directory" -d issues "${critical_dirs[@]}"

    if [[ "$issues" -eq 0 ]]; then
        log_pass "All critical system files and directories have verified secure permissions and ownership."
    fi
}

audit_temp_and_home_dirs() {
    step "4. Shared Temporary Directories Sticky Bit Check (/tmp, /var/tmp, /dev/shm):"
    local tdir
    for tdir in /tmp /var/tmp /dev/shm; do
        [[ -d "$tdir" ]] || continue
        if [[ -k "$tdir" ]]; then
            log_pass "Directory '${tdir}' sticky bit verified (Mode: $(file_mode "$tdir")). Users cannot delete each other's files."
        else
            log_crit "Directory '${tdir}' DOES NOT HAVE STICKY BIT SET (Mode: $(file_mode "$tdir"))! Local users can tamper with other users' temp files."
        fi
    done

    step "5. User Home Directories & Sensitive Dot-Folders Permissions (/home/*, /root):"
    local user uid home shell dot dot_path d_mode home_issues=0
    while IFS=: read -r user uid home shell; do
        [[ -d "$home" ]] || continue
        for dot in .ssh .gnupg .aws .kube .docker .config/gcloud; do
            dot_path="$home/$dot"
            [[ -d "$dot_path" ]] || continue
            d_mode=$(file_mode "$dot_path")
            if mode_has "$d_mode" 077; then
                log_warn "Sensitive directory '${dot_path}' has loose group/world permissions (${d_mode} $(stat -c %U:%G "$dot_path" 2>/dev/null)). Recommended: 700"
                home_issues=$((home_issues + 1))
            fi
        done
    done < <(human_accounts)
    if [[ "$home_issues" -eq 0 ]]; then
        log_pass "All user home directories and sensitive dot-folders have secure permissions."
    fi

    step "6. World-Writable Directories & Sticky Bit (+t) Integrity Audit:"
    # The root filesystem plus the usual separate mounts (-xdev keeps each scan on one
    # filesystem, so nothing is walked twice); /dev/shm is a tmpfs of its own
    local roots=(/) mp ww sd_private wdir wmode missing_sticky=0
    for mp in /home /var /opt /srv /usr /boot /tmp; do
        mountpoint -q "$mp" 2>/dev/null && roots+=("$mp")
    done
    ww=$( { find "${roots[@]}" -xdev -type d -perm -0002 2>/dev/null
            find /dev/shm -maxdepth 1 -type d -perm -0002 2>/dev/null; } | sort -u)
    sd_private=$(grep -c '/systemd-private-' <<< "$ww")
    ww=$(grep -v '/systemd-private-' <<< "$ww" | sed '/^$/d')
    [[ "$sd_private" -gt 0 ]] && echo -e "  - ${sd_private} per-service systemd PrivateTmp director(ies) (1777, sticky) collapsed"
    if [[ -z "$ww" ]]; then
        log_pass "No world-writable directories detected."
        return 0
    fi
    while read -r wdir; do
        wmode=$(file_mode "$wdir")
        if [[ -k "$wdir" ]]; then
            echo -e "  - World-Writable Dir: ${CYAN}${wdir}${NC} (Mode: ${wmode}) [${GREEN}Sticky bit +t set${NC}]"
        else
            log_crit "INSECURE WORLD-WRITABLE DIRECTORY: '${wdir}' (Mode: ${wmode}) is world-writable WITHOUT sticky bit (+t)! Any local user can delete or tamper with other users' files!"
            missing_sticky=$((missing_sticky + 1))
        fi
    done <<< "$ww"
    if [[ "$missing_sticky" -eq 0 ]]; then
        log_pass "All discovered world-writable directories have sticky bit (+t) enabled."
    fi
}

audit_package_integrity() {
    step "7. Critical System Binary Integrity Verification:"
    if have debsums; then
        echo "Running debsums integrity verification on system packages..."
        # stdout = files whose checksum really differs; stderr = "missing file" notes.
        # Missing files (e.g. docker-desktop's /DEBIAN/*, Papirus icons) are NOT modifications.
        local changed missing sys_changed other_changed
        local core_re='^/(usr/)?(bin|sbin|lib|lib64|libexec)/|^/usr/lib/|^/boot/'
        changed=$(debsums -c 2>"$WORK_DIR/debsums.err")
        missing=$(grep -c 'missing file' "$WORK_DIR/debsums.err" 2>/dev/null)
        if [[ -n "$changed" ]]; then
            sys_changed=$(grep -E "$core_re" <<< "$changed" | head -n 15)
            other_changed=$(grep -vE "$core_re" <<< "$changed" | head -n 15)
            [[ -n "$sys_changed" ]] && log_crit "System binaries/libraries differ from their package checksums (possible tampering):\n$sys_changed"
            [[ -n "$other_changed" ]] && log_warn "Package files modified locally (not core binaries):\n$other_changed"
        else
            log_pass "debsums integrity verification passed: no package file has a different checksum."
        fi
        if [[ "${missing:-0}" -gt 0 ]]; then
            log_info "debsums: ${missing} package file(s) are missing on disk (not counted as tampering; usually removed icons or packaging quirks, e.g. docker-desktop /DEBIAN/*)."
        fi
    elif have rpm; then
        local rpm_out
        rpm_out=$(rpm -Vf /bin/ls /bin/login /usr/sbin/sshd 2>/dev/null | grep -E '^..5')
        if [[ -n "$rpm_out" ]]; then
            log_crit "Modified system core binaries detected by RPM checksum check:\n$rpm_out"
        else
            log_pass "RPM core binary checksums verified."
        fi
    else
        echo -e "${YELLOW}debsums/rpm-verify not available for cryptographic binary checksum audit.${NC}"
    fi
}

audit_rotated_logs() {
    step "8. Rotated Logs Accumulation & Cleanup (/var/log):"
    local listing count total_bytes
    # "size path" of rotated/compressed archives
    listing=$(find /var/log -type f \( -name "*.gz" -o -name "*.1" -o -name "*.old" \) -size +0 -printf '%s %p\n' 2>/dev/null)
    if [[ -z "$listing" ]]; then
        log_pass "No accumulated rotated log archives in /var/log."
        return 0
    fi
    count=$(wc -l <<< "$listing")
    total_bytes=$(awk '{s += $1} END {print s + 0}' <<< "$listing")
    echo -e "Discovered ${count} rotated/compressed log file(s) occupying ${CYAN}$(human_size "$total_bytes")${NC} in /var/log."

    if [[ "$CLEAN_CACHE" == true ]]; then
        # Only archives older than 14 days: recent logs stay available for incident investigation
        local old_bytes
        old_bytes=$(find /var/log -type f \( -name "*.gz" -o -name "*.1" -o -name "*.old" \) -mtime +14 -printf '%s\n' -delete 2>/dev/null | awk '{s += $1} END {print s + 0}')
        log_pass "Rotated log archive cleanup completed (archives older than 14 days). Reclaimed $(human_size "$old_bytes") of disk space."
    else
        log_pass "Rotated logs monitored ($(human_size "$total_bytes"))."
    fi
}

audit_luks_keyfiles_in_tmp() {
    step "9. Auditing LUKS Cryptographic Keyfiles in Temporary Directories (/tmp, /var/tmp, /dev/shm):"
    local found=0 line target dev key_path

    # crypttab entries whose keyfile lives in a temporary directory
    if [[ -f /etc/crypttab ]]; then
        while read -r target dev key_path _; do
            [[ -z "$target" || "$target" == \#* ]] && continue
            if [[ "$key_path" =~ ^(/tmp/|/var/tmp/|/dev/shm/) ]]; then
                found=$((found + 1))
                log_crit "INSECURE CRYPTTAB KEYFILE: Target '${target}' in /etc/crypttab uses keyfile in temp directory: ${key_path}!"
            fi
        done < /etc/crypttab
    fi

    # Files named like LUKS/encryption keys
    local kfile k_mode
    while read -r kfile; do
        found=$((found + 1))
        k_mode=$(file_mode "$kfile")
        log_crit "LUKS / Encryption Keyfile detected in temporary directory: '${kfile}' (Permissions: ${k_mode}, Owner: $(stat -c %U:%G "$kfile" 2>/dev/null))!"
        if [[ "$AUTO_FIX" == true ]] && mode_has "$k_mode" 077; then
            chmod 600 "$kfile" 2>/dev/null && echo -e "  - ${GREEN}[OK] Auto-fix applied:${NC} Secured permissions of '${kfile}' to 600."
        fi
    done < <(find /tmp /var/tmp /dev/shm -maxdepth 3 -type f \( -iname "*luks*" -o -iname "*keyfile*" -o -iname "*crypt*key*" -o -iname "*volume.key" \) 2>/dev/null)

    # Binary LUKS headers / containers
    if have cryptsetup; then
        local cand
        while read -r cand; do
            if cryptsetup isLuks "$cand" 2>/dev/null; then
                found=$((found + 1))
                log_crit "LUKS Encrypted Volume Header / Container image found in temporary directory: '${cand}'!"
            fi
        done < <(find /tmp /var/tmp /dev/shm -maxdepth 2 -type f \( -name "*.img" -o -name "*.raw" -o -name "*.luks" -o -name "*.key" \) 2>/dev/null)
    fi

    if [[ "$found" -eq 0 ]]; then
        log_pass "No LUKS keyfiles or crypttab key references found in temporary directories (/tmp, /var/tmp, /dev/shm)."
    fi
}

audit_orphaned_files() {
    step "10. Orphaned Files & Directories Without Owner or Group Audit (-nouser / -nogroup):"
    local orphans
    orphans=$(find /etc /var /opt /home /tmp /usr /srv /boot -maxdepth 4 \( -nouser -o -nogroup \) 2>/dev/null | head -n 20)
    if [[ -n "$orphans" ]]; then
        log_warn "Orphaned files/directories without valid owner or group found ($(wc -l <<< "$orphans") items):\n$(sed 's/^/  - /' <<< "$orphans")"
    else
        log_pass "No orphaned files without owner or group (-nouser / -nogroup) found on the system."
    fi
}

section_filesystem() {
    audit_permissions_matrix
    audit_temp_and_home_dirs
    audit_package_integrity
    audit_rotated_logs
    audit_luks_keyfiles_in_tmp
    audit_orphaned_files
}

# --- External auditors ----------------------------------------------------------
section_external_auditors() {
    if have trivy; then
        echo -e "${CYAN}Running Trivy Container/Filesystem Audit...${NC}"
        trivy fs --severity HIGH,CRITICAL --format table "${SCRIPT_DIR}" 2>/dev/null
    else
        echo -e "${YELLOW}Trivy not installed - install trivy for vulnerability scanning of code/containers.${NC}"
    fi

    if ! have lynis; then
        echo -e "${YELLOW}Lynis security auditor not installed - install lynis for deep security scoring.${NC}"
        return 0
    fi
    echo -e "\n${CYAN}Running Lynis System Audit Summary...${NC}"
    lynis audit system --quick --no-colors 2>/dev/null | grep -E "Hardening index|Warnings|Suggestions"
    local report=/var/log/lynis-report.dat
    [[ -r "$report" ]] || return 0
    local lynis_warn lynis_sugg
    # Report lines look like "suggestion[]=ID|text|details|solution|"
    lynis_warn=$(grep -E '^warning\[\]=' "$report" | cut -d= -f2- | awk -F'|' '{print $1": "$2}' | cut -c1-150 | head -n 10)
    lynis_sugg=$(grep -E '^suggestion\[\]=' "$report" | cut -d= -f2- | awk -F'|' '{d = ($3 != "-" && $3 != "") ? " (" $3 ")" : ""; print $1": "$2 d}' | cut -c1-160 | head -n 10)
    [[ -n "$lynis_warn" ]] && log_warn "Lynis warnings:\n$(sed 's/^/  - /' <<< "$lynis_warn")"
    [[ -n "$lynis_sugg" ]] && echo -e "  Top Lynis suggestions (first 10; full list: ${report}):\n$(sed 's/^/    - /' <<< "$lynis_sugg")"
}

# --- Logins, sessions, boots & auth logs ----------------------------------------
LAST_OUTPUT=""
LAST_LOADED=false
# Login history from wtmp/wtmpdb, read once: `last -w` (full user names), without the trailer line
wtmp_log() {
    if [[ "$LAST_LOADED" != true ]]; then
        LAST_LOADED=true
        have last && LAST_OUTPUT=$(last -w 2>/dev/null | grep -vE '^$|^wtmp(db)? begins')
    fi
    [[ -n "$LAST_OUTPUT" ]] && printf '%s\n' "$LAST_OUTPUT"
}

audit_unclean_shutdowns() {
    have journalctl || return 0
    # 'crash' in last is unreliable (GNOME leaves wtmp records open on clean reboots),
    # so judge each previous boot by whether its journal reached the systemd shutdown
    local offsets off tail_lines unclean=""
    offsets=$(journalctl --list-boots --no-pager 2>/dev/null | awk '$1 ~ /^-[0-9]+$/ {print $1}' | tail -n 10)
    for off in $offsets; do
        tail_lines=$(journalctl -b "$off" -n 40 -q --no-pager 2>/dev/null)
        [[ -n "$tail_lines" ]] || continue
        matches 'systemd-shutdown|Journal stopped|Reached target .*(Power-Off|Reboot|Halt|Shutdown)' "$tail_lines" && continue
        unclean+="    - boot ${off}: last entry $(tail -n 1 <<< "$tail_lines" | cut -c1-15)\n"
    done
    if [[ -n "$unclean" ]]; then
        log_warn "Previous boot(s) ended without a clean shutdown (freeze / power loss / kernel panic):\n${unclean}  Inspect: journalctl -b <offset> -e"
    elif [[ -n "$offsets" ]]; then
        log_pass "Last $(wc -w <<< "$offsets") boot(s) ended with a clean shutdown/reboot."
    fi
}

audit_auth_logs() {
    subsection "Scanning System Logs for Security Anomaly Indicators"
    local auth_re='authentication failure|Failed password|Invalid user|FAILED LOGIN|NOT in sudoers|maximum authentication attempts|incorrect password attempts|Failed publickey'
    local remote_re='Failed password|Invalid user|Failed publickey|maximum authentication attempts'
    local crash_re='segfault|Out of memory: Kill process|general protection fault|kernel BUG|Oops:'

    if have journalctl; then
        echo -e "${CYAN}Scanning systemd journal (last 24h)...${NC}"

        # 1. Authentication failures (PAM, sshd, su, sudo, login, display manager, screen lock)
        local auth_lines auth_count remote_count
        auth_lines=$(journalctl --since "24 hours ago" --no-pager -o cat -g "$auth_re" 2>/dev/null | sed '/^$/d')
        auth_count=$(grep -c . <<< "$auth_lines")
        remote_count=$(grep -cE "$remote_re" <<< "$auth_lines")
        echo -e "Authentication failures (24h): ${CYAN}${auth_count}${NC} (remote/ssh-style: ${CYAN}${remote_count}${NC})"

        if [[ "$remote_count" -gt 20 ]]; then
            log_crit "${remote_count} remote-style authentication failures in 24h - possible brute-force attack."
        elif [[ "$auth_count" -gt 0 ]]; then
            echo "  Top sources:"
            sed -E 's/[0-9]+/N/g' <<< "$auth_lines" | cut -c1-110 | sort | uniq -c | sort -rn | head -n 5 | sed 's/^/    /'
            if [[ "$auth_count" -gt 20 ]]; then
                log_warn "${auth_count} local authentication failures in 24h (mistyped sudo/unlock passwords or a misbehaving service). No remote-login pattern found."
            else
                log_pass "Only ${auth_count} local authentication failure(s) in 24h; no brute-force pattern."
            fi
        else
            log_pass "No authentication failures in the journal (last 24h)."
        fi

        # 2. Crashes / OOM / kernel faults
        local crash_lines
        crash_lines=$(journalctl --since "24 hours ago" --no-pager -o short-iso -p warning..emerg -g "$crash_re" 2>/dev/null | grep -v '^-- ' | tail -n 10)
        if [[ -n "$crash_lines" ]]; then
            log_warn "Crash / OOM / kernel-fault entries in the journal (last 24h):\n$crash_lines"
        else
            log_pass "No crash, OOM or kernel-fault entries in the journal (last 24h)."
        fi

        # 3. Mandatory-access-control denials (informational)
        local denied
        denied=$(journalctl -k --since "24 hours ago" --no-pager -o cat -g 'apparmor="DENIED"' 2>/dev/null | grep -c .)
        [[ "$denied" -gt 0 ]] && log_info "AppArmor logged ${denied} DENIED event(s) in 24h (review with: journalctl -k -g 'apparmor=\"DENIED\"')."
    fi

    local logfile matches_found
    for logfile in /var/log/auth.log /var/log/secure; do
        [[ -f "$logfile" ]] || continue
        echo -e "\n${CYAN}Scanning security log file ${logfile}...${NC}"
        matches_found=$(grep -E "$auth_re" "$logfile" 2>/dev/null | tail -n 10)
        if [[ -n "$matches_found" ]]; then
            log_warn "Recent authentication failures in ${logfile}:\n$matches_found"
        else
            log_pass "No authentication failures found in ${logfile}."
        fi
    done

    subsection "Recent Sudo Usage & Privilege Escalation"
    local sudo_lines=""
    if [[ -f /var/log/secure ]]; then
        sudo_lines=$(grep "sudo" /var/log/secure 2>/dev/null | tail -n 10)
    elif [[ -f /var/log/auth.log ]]; then
        sudo_lines=$(grep "sudo" /var/log/auth.log 2>/dev/null | tail -n 10)
    elif have journalctl; then
        sudo_lines=$(journalctl _COMM=sudo -n 10 --no-pager 2>/dev/null)
    fi
    echo "${sudo_lines:-No sudo records found.}"
}

section_logins() {
    step "1. Currently Active Logged-In Users & Sessions (who / w):"
    if have who; then
        local sessions
        sessions=$(who 2>/dev/null)
        if [[ -n "$sessions" ]]; then
            who -H 2>/dev/null
            log_pass "Currently active user sessions: $(wc -l <<< "$sessions")"
            matches '^root[[:space:]]' "$sessions" && log_warn "Root account has an active interactive login session!"
        else
            echo "No active interactive login sessions."
        fi
    elif have w; then
        w 2>/dev/null
    fi

    step "2. Recent Successful User Logins (last 10 sessions):"
    local recent
    recent=$(wtmp_log | head -n 10)
    if [[ -n "$recent" ]]; then
        echo "$recent"
        local remote
        remote=$(grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$recent")
        [[ -n "$remote" ]] && echo -e "${YELLOW}Remote IP Login Sessions Discovered:${NC}\n$remote"
    else
        echo "No recent login records available."
    fi
    audit_unclean_shutdowns

    step "3. Failed Login Attempts Audit (btmp):"
    if have lastb; then
        local failed failed_n
        failed=$(lastb -s -24hours 2>/dev/null | grep -vE '^$|btmp begins')
        failed_n=$(grep -c . <<< "$failed")
        if [[ "$failed_n" -gt 50 ]]; then
            log_crit "${failed_n} failed logins in the last 24h recorded in btmp - potential brute-force attack."
        elif [[ "$failed_n" -gt 0 ]]; then
            log_warn "${failed_n} failed login(s) in the last 24h recorded in btmp:\n$(head -n 10 <<< "$failed")"
        else
            log_pass "No failed logins in the last 24h in the btmp database."
        fi
    else
        log_skip "lastb is not installed on this system - btmp cannot be read. Failed logins are evaluated from the journal in the log scan below (not counted as a pass)."
    fi

    step "4. Interactive Accounts Login Activity & Inactive Users Audit:"
    echo "Auditing login timestamps for interactive shell accounts..."
    local user uid home shell entry
    while IFS=: read -r user uid home shell; do
        has_login_shell "$shell" || continue
        if have lastlog; then
            entry=$(lastlog -u "$user" 2>/dev/null | tail -n 1)
        elif have lastlog2; then
            entry=$(lastlog2 --user "$user" 2>/dev/null | tail -n 1)
        elif have last; then
            entry=$(wtmp_log | awk -v u="$user" '$1 == u {print; exit}')
            [[ -z "$entry" ]] && entry="**Never logged in**"
        else
            entry="(no lastlog/lastlog2/last tool available)"
        fi

        if [[ "$entry" == *"Never logged in"* ]]; then
            if [[ "$uid" -ge 1000 ]]; then
                log_warn "Interactive user '${user}' (UID ${uid}) has NEVER logged in!"
            else
                echo -e "  - System account ${CYAN}${user}${NC} (UID ${uid}): never logged in (normal)."
            fi
        else
            echo -e "  - User ${CYAN}${user}${NC}: ${entry}"
        fi
    done < <(all_accounts)

    audit_auth_logs
}

# --- Resources ------------------------------------------------------------------
audit_time_sync() {
    subsection "System Timezone & Time Synchronization Audit"
    local tz_abbr tz_offset tz_name synced=false
    tz_abbr=$(date "+%Z")
    tz_offset=$(date "+%z")
    if [[ -L /etc/localtime ]]; then
        tz_name=$(readlink -f /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||')
    elif [[ -f /etc/timezone ]]; then
        tz_name=$(cat /etc/timezone 2>/dev/null)
    fi
    tz_name=${tz_name:-$tz_abbr}
    echo -e "  Configured Timezone        : ${CYAN}${tz_name}${NC} (${tz_abbr}, UTC${tz_offset})"

    if have timedatectl; then
        local status ntp_sync ntp_service
        status=$(timedatectl status 2>/dev/null)
        ntp_sync=$(awk -F': ' '/System clock synchronized:/ {print $2}' <<< "$status")
        ntp_service=$(awk -F': ' '/NTP service:/ {print $2}' <<< "$status")
        echo -e "  NTP Time Sync Service      : ${CYAN}${ntp_service:-unknown}${NC}"
        echo -e "  System Clock Synchronized  : ${CYAN}${ntp_sync:-unknown}${NC}"
        [[ "$ntp_sync" == "yes" ]] && synced=true
    elif unit_active systemd-timesyncd || unit_active chronyd || unit_active ntp; then
        synced=true
    fi

    if [[ "$synced" == true ]]; then
        log_pass "Timezone configuration ('${tz_name}') verified & system clock is synchronized via NTP."
    else
        log_warn "Timezone is configured ('${tz_name}'), but system clock is NOT synchronized with NTP servers!"
    fi
}

audit_disk_usage() {
    subsection "Disk Space Usage & Free Space Check"
    local df_out alerts="" fs size used avail pct mount
    df_out=$(df -h -x tmpfs -x devtmpfs -x squashfs 2>/dev/null)
    echo "$df_out"
    while read -r fs size used avail pct mount; do
        pct=${pct%\%}
        if [[ "$pct" =~ ^[0-9]+$ && "$pct" -ge 80 ]]; then
            alerts+="Partition ${mount} (${fs}) is ${pct}% full! (Free: ${avail} / ${size}, Used: ${used})\n"
        fi
    done < <(tail -n +2 <<< "$df_out")

    if [[ -n "$alerts" ]]; then
        log_warn "High disk usage detected (>= 80% occupied):\n$alerts"
    else
        log_pass "All disk partitions have sufficient free space (< 80% used)."
    fi
}

audit_failed_units() {
    subsection "Systemd Failed Services"
    have systemctl || return 0
    local failed unit
    failed=$(systemctl --failed --no-legend --plain 2>/dev/null)
    if [[ -z "$failed" ]]; then
        log_pass "No failed systemd services."
        return 0
    fi
    log_warn "Found failed systemd services:\n$failed"
    if [[ "$AUTO_RESTART_SERVICES" == true ]]; then
        echo -e "${YELLOW}Attempting automatic recovery/restart of failed systemd services...${NC}"
        while read -r unit _; do
            [[ -n "$unit" ]] && restart_service "$unit" "recovering failed unit"
        done <<< "$failed"
    else
        echo -e "${YELLOW}Tip: run with --restart-services to auto-restart failed units.${NC}"
    fi
}

audit_user_caches() {
    subsection "User Home Directory Cache & Temporary Files Audit"
    local cache_targets=(
        ".cache/thumbnails"
        ".local/share/Trash"
        ".cache/pip"
        ".cache/npm"
        ".cache/yarn"
        ".cache/pnpm"
        ".cache/go-build"
        ".cache/crash"
        ".local/share/crash"
        ".cache/Code/Cache"
        ".cache/Code/CachedData"
        ".cache/google-chrome/Default/Cache"
        ".cache/google-chrome/Profile */Cache"
        ".cache/chromium/Default/Cache"
        ".cache/mozilla/firefox/*/cache2"
    )
    local total_bytes=0 found=() user uid home shell rel target size_bytes size_human core
    while IFS=: read -r user uid home shell; do
        [[ -d "$home" ]] || continue
        for rel in "${cache_targets[@]}"; do
            # Unquoted on purpose: the targets contain globs (Profile */, firefox/*/)
            for target in $home/$rel; do
                [[ -e "$target" ]] || continue
                size_bytes=$(du -sb "$target" 2>/dev/null | awk '{print $1}')
                [[ -n "$size_bytes" && "$size_bytes" -gt 1048576 ]] || continue
                size_human=$(human_size "$size_bytes")
                total_bytes=$((total_bytes + size_bytes))
                found+=("${user} -> ${target} (${size_human})")
                if [[ "$CLEAN_CACHE" == true ]]; then
                    echo -n "  Cleaning ${target} (${size_human})... "
                    if [[ -d "$target" ]]; then
                        find "$target" -mindepth 1 -delete 2>/dev/null
                    else
                        rm -f "$target" 2>/dev/null
                    fi
                    echo -e "${GREEN}Cleaned${NC}"
                fi
            done
        done

        while read -r core; do
            size_human=$(du -sh "$core" 2>/dev/null | awk '{print $1}')
            found+=("${user} -> Core Dump ${core} (${size_human})")
            if [[ "$CLEAN_CACHE" == true ]]; then
                rm -f "$core" 2>/dev/null
                echo -e "  Deleted core dump ${core} (${size_human}): ${GREEN}Cleaned${NC}"
            fi
        done < <(find "$home" -maxdepth 2 -type f \( -name "core" -o -regex '.*/core\.[0-9]+' \) 2>/dev/null)
    done < <(human_accounts)

    if [[ ${#found[@]} -eq 0 ]]; then
        log_pass "User home directories have no accumulated temporary caches (> 1MB)."
    elif [[ "$CLEAN_CACHE" == true ]]; then
        log_pass "User home directory cache cleanup completed. Total reclaimed space: $(human_size "$total_bytes")"
    else
        echo -e "${CYAN}Discovered User Home Directory Caches ($(human_size "$total_bytes") reclaimable):${NC}"
        printf '  - %s\n' "${found[@]}"
        log_warn "User home directories contain $(human_size "$total_bytes") of temporary cache files."
        echo -e "  ${YELLOW}Tip: Run the script with '--clean-cache' to automatically purge these caches.${NC}"
    fi
}

section_resources() {
    audit_time_sync
    audit_disk_usage
    audit_failed_units

    subsection "Systemd Journal Disk Usage"
    if have journalctl; then
        journalctl --disk-usage 2>/dev/null
        echo "Tip: Run 'sudo journalctl --vacuum-time=2weeks' or '--vacuum-size=500M' if journal size is too large."
    fi

    subsection "Package Cache & Unused Packages"
    local unneeded=""
    case "$PKG_MGR" in
        apt) unneeded=$(apt-get autoremove --dry-run 2>/dev/null | grep -E "^Remv " | head -n 5) ;;
        dnf) unneeded=$(dnf autoremove --assumeno 2>/dev/null | grep -E "^Removing" | head -n 5) ;;
    esac
    if [[ -n "$unneeded" ]]; then
        log_warn "Orphaned/unused packages detected. Consider running '${PKG_MGR} autoremove'."
    elif [[ -n "$PKG_MGR" ]]; then
        log_pass "Package database clean."
    fi

    audit_user_caches
}

# --- Accounts, groups, passwords, sudoers & PAM ---------------------------------
audit_passwd_entries() {
    subsection "/etc/passwd Accounts & Interactive Shell Audit"
    local uid_zero dup_uids dup_users legacy
    uid_zero=$(awk -F: '$3 == "0" && $1 != "root" {print $1}' /etc/passwd)
    dup_uids=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
    dup_users=$(cut -d: -f1 /etc/passwd | sort | uniq -d)
    legacy=$(awk -F: '$2 != "x" && $2 != "*" && $2 != "!" {print $1}' /etc/passwd)

    if [[ -n "$uid_zero" ]]; then log_crit "Non-root users with UID 0 found: ${uid_zero}"; else log_pass "Only 'root' user has UID 0."; fi
    if [[ -n "$dup_uids" ]]; then log_crit "Duplicate UIDs found in /etc/passwd: ${dup_uids}"; else log_pass "No duplicate UIDs found in /etc/passwd."; fi
    if [[ -n "$dup_users" ]]; then log_crit "Duplicate usernames found in /etc/passwd: ${dup_users}"; else log_pass "No duplicate usernames found in /etc/passwd."; fi
    if [[ -n "$legacy" ]]; then
        log_crit "Accounts with unencrypted password hashes directly in /etc/passwd: ${legacy}"
    else
        log_pass "No legacy unencrypted password hashes stored in /etc/passwd (shadow mode active)."
    fi

    step "Accounts with Console / Interactive Shell Access:"
    local user uid gid home shell sudo_state pw_state
    local sys_interactive=() missing_shells=() bad_homes=()
    while IFS=: read -r user _ uid gid _ home shell; do
        has_login_shell "$shell" || continue

        sudo_state="No"
        if [[ "$uid" -eq 0 ]]; then
            sudo_state="${RED}YES (ROOT)${NC}"
        elif user_is_admin "$user"; then
            sudo_state="${YELLOW}YES (Sudo Group)${NC}"
        fi
        case "$(passwd -S "$user" 2>/dev/null | awk '{print $2}')" in
            L|LK) pw_state="${YELLOW}Locked${NC}" ;;
            P|PS) pw_state="${GREEN}Password Set${NC}" ;;
            NP)   pw_state="${RED}NO PASSWORD!${NC}" ;;
            *)    pw_state="Unknown" ;;
        esac
        echo -e "  - ${CYAN}${user}${NC} (UID: ${uid}, GID: ${gid}, Shell: ${shell})"
        echo -e "    Home: ${home} | Sudo Privileges: ${sudo_state} | Password Status: ${pw_state}"

        [[ "$uid" -ne 0 && "$uid" -lt 1000 ]] && sys_interactive+=("${user} (UID: ${uid})")
        [[ -x "$shell" ]] || missing_shells+=("${user} -> ${shell}")
        if [[ "$home" == "/" || "$home" =~ ^/(tmp|var/tmp|dev/shm) || ! -d "$home" ]]; then
            bad_homes+=("${user} -> ${home}")
        fi
        if ! awk -F: -v g="$gid" '$3 == g {found = 1} END {exit !found}' /etc/group; then
            log_warn "User '${user}' has primary GID ${gid} which does NOT exist in /etc/group!"
        fi
    done < /etc/passwd

    if [[ ${#sys_interactive[@]} -gt 0 ]]; then
        log_warn "System accounts (UID < 1000) with interactive login shells detected: ${sys_interactive[*]}"
    else
        log_pass "No system service accounts (UID < 1000) have interactive login shells."
    fi
    [[ ${#missing_shells[@]} -gt 0 ]] && log_warn "Users assigned non-existent or non-executable shells: ${missing_shells[*]}"
    if [[ ${#bad_homes[@]} -gt 0 ]]; then
        log_warn "Interactive users with suspicious or missing home directories: ${bad_homes[*]}"
    else
        log_pass "All interactive shell users have valid home directories."
    fi
}

audit_groups() {
    subsection "/etc/group & Privileged Group Audit"
    local dup_gids dup_names zero_gids
    dup_gids=$(cut -d: -f3 /etc/group | sort | uniq -d)
    dup_names=$(cut -d: -f1 /etc/group | sort | uniq -d)
    zero_gids=$(awk -F: '$3 == "0" && $1 != "root" {print $1}' /etc/group)
    if [[ -n "$dup_gids" ]]; then log_warn "Duplicate GIDs found in /etc/group: ${dup_gids}"; else log_pass "No duplicate GIDs in /etc/group."; fi
    [[ -n "$dup_names" ]] && log_crit "Duplicate group names in /etc/group: ${dup_names}"
    [[ -n "$zero_gids" ]] && log_warn "Non-root groups with GID 0: ${zero_gids}"

    echo -e "${CYAN}Auditing Privileged & Sensitive System Group Memberships:${NC}"
    local grp line gid members primary all
    for grp in sudo wheel admin docker podman shadow disk kmem input kvm adm systemd-journal; do
        line=$(grep -m1 "^${grp}:" /etc/group) || continue
        gid=$(cut -d: -f3 <<< "$line")
        members=$(cut -d: -f4 <<< "$line")
        # Users whose PRIMARY group this is are members too
        primary=$(awk -F: -v g="$gid" '$4 == g {print $1}' /etc/passwd | paste -sd, -)
        all=$(printf '%s\n%s\n' "$primary" "$members" | tr ',' '\n' | sed '/^$/d' | sort -u | paste -sd, -)
        if [[ -z "$all" ]]; then
            echo -e "  - Group ${CYAN}${grp}${NC} (GID ${gid}): (No members)"
            continue
        fi
        echo -e "  - Group ${CYAN}${grp}${NC} (GID ${gid}): ${all}"
        case "$grp" in
            shadow|disk|kmem) log_warn "Group '${grp}' gives raw disk/shadow access! Members: ${all}" ;;
            docker)           log_warn "Group 'docker' gives root-equivalent host privileges! Members: ${all}" ;;
        esac
    done
}

audit_user_privileges() {
    subsection "User Accounts, Privileges, Group Memberships & Login Frequency Audit"
    local -A login_count=() last_login=()
    local name rest
    # wtmp records per user (reboot/shutdown pseudo-users excluded)
    while read -r name rest; do
        [[ -z "$name" || "$name" == "reboot" || "$name" == "shutdown" ]] && continue
        login_count[$name]=$(( ${login_count[$name]:-0} + 1 ))
        [[ -z "${last_login[$name]:-}" ]] && last_login[$name]=$(awk '{for (i = 2; i <= NF; i++) printf "%s ", $i}' <<< "$rest")
    done < <(wtmp_log)

    echo -e "${CYAN}Per-User Account Details (UID, Groups, Privileges, Login Count):${NC}"
    local user uid home shell groups priv total=0 privileged=0
    while IFS=: read -r user uid home shell; do
        [[ "$uid" -eq 65534 ]] && continue
        [[ "$uid" -ge 1000 || "$uid" -eq 0 || "$shell" =~ (bash|zsh|sh|csh|tcsh|ksh)$ ]] || continue
        total=$((total + 1))
        groups=$(id -Gn "$user" 2>/dev/null | tr ' ' ',')
        groups=${groups:-"(unknown)"}

        priv=""
        [[ "$uid" -eq 0 ]] && priv+=" [UID 0 ROOT]"
        [[ ",${groups}," =~ ,(sudo|wheel|admin), ]] && priv+=" [SUDOERS ACCESS]"
        [[ ",${groups}," =~ ,(docker|containerd|podman), ]] && priv+=" [DOCKER/CONTAINER HOST ACCESS]"
        [[ ",${groups}," =~ ,(shadow|disk|kmem), ]] && priv+=" [RAW DISK/SHADOW ACCESS]"

        echo -e "  - User: ${CYAN}${user}${NC} (UID: ${uid}, Shell: ${shell})"
        if [[ -n "$priv" ]]; then
            privileged=$((privileged + 1))
            echo -e "    Groups       : ${YELLOW}${groups}${NC}"
            echo -e "    Privileges   : ${RED}${priv# }${NC}"
        else
            echo -e "    Groups       : ${GREEN}${groups}${NC}"
            echo -e "    Privileges   : Standard User"
        fi
        echo -e "    Total Logins : ${CYAN}${login_count[$user]:-0} session(s)${NC} (Last: ${last_login[$user]:-No recent logins recorded})"
    done < <(all_accounts)

    if [[ "$privileged" -gt 2 ]]; then
        log_warn "Discovered ${privileged} privileged/administrative accounts (root included) out of ${total} user account(s). Review who really needs sudo/docker."
    elif [[ "$privileged" -gt 0 ]]; then
        log_pass "Privileged accounts: ${privileged} of ${total} (root + the expected admin user(s))."
    else
        log_pass "User privileges audit completed: ${total} interactive user account(s) evaluated."
    fi
}

fetch_external_password_lists() {
    echo -e "${YELLOW}--- Weak Password Dictionary Cache (GitHub sources) ---${NC}"
    mkdir -p "$DICT_CACHE_DIR" 2>/dev/null
    chmod 700 "$DICT_CACHE_DIR" 2>/dev/null

    # Do not touch the network/cache unless explicitly requested
    if [[ "$REFRESH_EXTERNAL_PASSWORDS" != true ]]; then
        if [[ -s "$DICT_FILE" ]]; then
            echo -e "  ${CYAN}Using existing cached dictionary; refresh only with --refresh-dict.${NC}"
        else
            echo -e "  ${YELLOW}No cached dictionary found; refresh only with --refresh-dict.${NC}"
        fi
        return 0
    fi
    if ! have curl && ! have wget; then
        echo -e "  ${YELLOW}Neither curl nor wget available: cannot refresh dictionary cache.${NC}"
        return 0
    fi

    local start elapsed url fname dest local_size downloaded=0 skipped=0 failed=0
    local raw_files=()
    start=$(date +%s)
    for url in "${EXTERNAL_PASSWORD_LIST_URLS[@]}"; do
        elapsed=$(( $(date +%s) - start ))
        if [[ "$elapsed" -ge "$DICT_DOWNLOAD_TIMEOUT_SEC" ]]; then
            echo -e "  ${YELLOW}! Download budget (${DICT_DOWNLOAD_TIMEOUT_SEC}s) reached; continuing with sources fetched so far.${NC}"
            break
        fi
        fname="${url##*/}"
        dest="$DICT_CACHE_DIR/$fname"

        # Cache hit: the cached file size matches the remote size
        if [[ -s "$dest" ]]; then
            local_size=$(stat -c %s "$dest" 2>/dev/null)
            if [[ "$(remote_size "$url")" == "$local_size" ]]; then
                echo -e "  - ${CYAN}${fname}${NC}: cache up to date (${local_size} bytes) - download skipped."
                skipped=$((skipped + 1))
                raw_files+=("$dest")
                continue
            fi
        fi

        echo -n "  Downloading ${fname}... "
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
        echo -n "  Building combined dictionary (deduplicated, sorted)... "
        cat "${raw_files[@]}" 2>/dev/null | tr -d '\r' | grep -vE '^[[:space:]]*(#|$)' | sort -u > "${DICT_FILE}.tmp"
        if [[ -s "${DICT_FILE}.tmp" ]]; then
            mv -f "${DICT_FILE}.tmp" "$DICT_FILE"
            chmod 600 "$DICT_FILE"
            echo -e "${GREEN}OK${NC} ($(stat -c %s "$DICT_FILE") bytes, $(wc -l < "$DICT_FILE") unique passwords)"
        else
            rm -f "${DICT_FILE}.tmp"
            echo -e "${YELLOW}FAILED (kept previous dictionary if any)${NC}"
        fi
    fi
    echo -e "  Dictionary cache summary: ${CYAN}${downloaded} downloaded, ${skipped} reused from cache, ${failed} failed${NC}"
    echo -e "  Cached dictionary file: ${CYAN}${DICT_FILE}${NC} (kept for future runs)"
}

# Tries common/dictionary passwords against every active /etc/shadow hash via libcrypt.
# argv: hostname, dictionary file (may be empty). Output: KEY:value lines parsed by the caller.
read -r -d '' WEAK_PASSWORD_PY << 'PYEOF'
import sys, ctypes, ctypes.util, os, time
import multiprocessing as mp

hostname = sys.argv[1] if len(sys.argv) > 1 else ""
dict_file = sys.argv[2] if len(sys.argv) > 2 else ""
BUDGET_SEC = 240          # per-account time budget

libname = ctypes.util.find_library('crypt')
_lib = None

def _load():
    global _lib
    if _lib is None and libname:
        try:
            l = ctypes.CDLL(libname)
            l.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            l.crypt.restype = ctypes.c_char_p
            _lib = l
        except Exception:
            _lib = None
    return _lib

def _worker(task):
    h, pws = task
    l = _load()
    if not l:
        return (None, 0)
    hb = h.encode()
    n = 0
    for p in pws:
        n += 1
        r = l.crypt(p.encode('utf-8', 'ignore'), hb)
        if r and r.decode('utf-8', 'ignore') == h:
            return (p, n)
    return (None, n)

common_passwords = [
    '123456', 'password', 'qwerty', 'admin', '12345678', 'root',
    'pass123', 'P@ssword', '123456789', 'system', '12345', 'letmein',
    'welcome', 'master', 'administrator', 'changeme', 'ubuntu', 'debian',
    'fedora', 'centos', 'redhat', 'user', 'test', 'demo', 'login', 'pass',
    'password123', 'admin123', 'root123', '1234', '1234567', '1234567890'
]
if hostname:
    common_passwords.append(hostname.lower())

if dict_file and os.path.exists(dict_file):
    try:
        added = 0
        with open(dict_file, 'r', errors='ignore') as df:
            for line in df:
                p = line.strip()
                if p:
                    common_passwords.append(p)
                    added += 1
        print(f"DICT_LOADED:{added}")
    except Exception as err:
        print(f"DICT_ERR:{err}")

print("CRYPT_AVAILABLE:" + ("1" if _load() else "0"))

weak_found = []
partial = []
algo_counts = {}
base = list(dict.fromkeys(common_passwords))
workers = max(1, (os.cpu_count() or 2))
# The script comes from stdin: workers must be forked (spawn/forkserver cannot re-import it)
ctx = mp.get_context('fork')

if os.path.exists('/etc/shadow'):
    with open('/etc/shadow', 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) < 2:
                continue
            user, hash_val = parts[0], parts[1]
            if not hash_val or hash_val.startswith(('!', '*', 'x')):
                continue
            algo = "Unknown"
            if hash_val.startswith('$y$'): algo = "Yescrypt"
            elif hash_val.startswith('$6$'): algo = "SHA-512"
            elif hash_val.startswith('$5$'): algo = "SHA-256"
            elif hash_val.startswith('$1$'): algo = "MD5 (Obsolete)"
            elif hash_val.startswith('$2a$') or hash_val.startswith('$2b$'): algo = "Bcrypt"
            elif len(hash_val) == 13: algo = "DES (Obsolete)"
            algo_counts[algo] = algo_counts.get(algo, 0) + 1

            if not _load():
                continue
            cand = list(dict.fromkeys(base + [user, f'{user}123', f'{user}2025', f'{user}2026', f'{user}!', f'{user}1']))
            chunk = 64
            tasks = [(hash_val, cand[i:i + chunk]) for i in range(0, len(cand), chunk)]
            tested = 0
            hit = None
            t0 = time.time()
            with ctx.Pool(workers) as pool:
                for pw, n in pool.imap_unordered(_worker, tasks):
                    tested += n
                    if pw is not None:
                        hit = pw
                        break
                    if time.time() - t0 > BUDGET_SEC:
                        break
            if hit is not None:
                weak_found.append((user, hit))
            elif tested < len(cand):
                partial.append((user, tested, len(cand)))

print("TOTAL_PASSWORDS:" + str(len(set(common_passwords))))
print("ALGOS:" + ",".join([f"{k}:{v}" for k, v in algo_counts.items()]))
for u, p in weak_found:
    print(f"WEAK:{u}:{p}")
for u, a, b in partial:
    print(f"PARTIAL:{u}:{a}:{b}")
PYEOF

audit_weak_passwords() {
    if ! have python3; then
        echo -e "${YELLOW}python3 not installed. Skipping automated weak password dictionary scan.${NC}"
        return 0
    fi
    echo -e "${CYAN}Executing dictionary & pattern check for weak user passwords...${NC}"
    local dict_arg=""
    if [[ "$FETCH_EXTERNAL_PASSWORDS" == true && ${#EXTERNAL_PASSWORD_LIST_URLS[@]} -gt 0 ]]; then
        fetch_external_password_lists
        dict_arg="$DICT_FILE"
    fi

    local result
    result=$(timeout 600s python3 - "$(hostname 2>/dev/null)" "$dict_arg" <<< "$WEAK_PASSWORD_PY" 2>/dev/null)
    [[ -n "$result" ]] || return 0

    local value
    value=$(sed -n 's/^DICT_LOADED://p' <<< "$result")
    [[ -n "$value" ]] && echo -e "  - ${GREEN}[OK] [DICTIONARY]${NC} Loaded ${CYAN}${value}${NC} unique passwords from cached combined dictionary."
    value=$(sed -n 's/^DICT_ERR://p' <<< "$result")
    [[ -n "$value" ]] && echo -e "  - ${YELLOW}! [DICTIONARY ERROR]${NC} Could not read ${DICT_FILE}: ${value}"
    value=$(sed -n 's/^TOTAL_PASSWORDS://p' <<< "$result")
    [[ -n "$value" ]] && echo -e "  Total unique dictionary passwords evaluated: ${CYAN}${value}${NC}"

    local algos
    algos=$(sed -n 's/^ALGOS://p' <<< "$result")
    if [[ -n "$algos" ]]; then
        echo -e "  Active password hashing algorithms in use: ${CYAN}${algos}${NC}"
        matches 'MD5|DES' "$algos" && log_warn "Obsolete password hashing algorithms detected in shadow file (${algos}). Upgrade to SHA-512 or Yescrypt."
    fi

    local weak_users user
    weak_users=$(awk -F: '/^WEAK:/ {print $2}' <<< "$result")
    if [[ -n "$weak_users" ]]; then
        # Never write the matched password itself into the report
        while read -r user; do
            log_crit "WEAK PASSWORD DETECTED for user '${user}': password matches a common dictionary pattern. Change it immediately."
        done <<< "$weak_users"
    elif matches '^CRYPT_AVAILABLE:0' "$result"; then
        log_warn "Weak-password check could NOT run: libcrypt is not loadable from python3 (result is unknown, not 'clean')."
    elif matches '^PARTIAL:' "$result"; then
        log_warn "Weak-password dictionary check hit its time budget (partial coverage): $(grep '^PARTIAL:' <<< "$result" | tr '\n' ' ')"
    else
        log_pass "Password strength dictionary scan completed: No common weak passwords found for active user accounts."
    fi
}

audit_shadow_passwords() {
    subsection "/etc/shadow Password Security & Weak Password Audit"
    if [[ ! -r /etc/shadow ]]; then
        log_warn "Cannot read /etc/shadow (root/sudo required). Skipping shadow hash & weak password analysis."
        return 0
    fi

    local empty
    empty=$(awk -F: '$2 == "" || $2 == "NP" {print $1}' /etc/shadow)
    if [[ -n "$empty" ]]; then
        log_crit "Accounts with NO PASSWORD set in /etc/shadow: ${empty}"
    else
        log_pass "No active user accounts have empty password fields in /etc/shadow."
    fi

    audit_weak_passwords

    step "Password Aging & Expiration Audit (/etc/shadow):"
    local today expired="" no_max="" user pass lstchg max
    today=$(( $(date +%s) / 86400 ))
    while IFS=: read -r user pass lstchg _ max _; do
        [[ -z "$user" || "$pass" == [\!\*]* ]] && continue
        if [[ "$max" =~ ^[0-9]+$ && "$max" -ne 99999 && "$lstchg" =~ ^[0-9]+$ && "$lstchg" -gt 0 ]]; then
            if [[ "$today" -ge $(( lstchg + max )) ]]; then
                expired+="${user} (Expired $(( today - lstchg - max )) days ago)\n"
            fi
        elif [[ -z "$max" || "$max" == "99999" ]]; then
            no_max+="${user} "
        fi
    done < /etc/shadow
    if [[ -n "$expired" ]]; then
        log_warn "User accounts with EXPIRED passwords:\n$expired"
    else
        log_pass "No active user accounts have expired passwords."
    fi
    [[ -n "$no_max" ]] && echo -e "  - Accounts without password expiration limit (Max=99999): ${CYAN}${no_max}${NC}"
}

# login_def KEY: value of KEY in /etc/login.defs (empty if unset)
login_def() { awk -v k="$1" '$1 == k {print $2; exit}' /etc/login.defs 2>/dev/null; }

audit_login_defs() {
    subsection "System Password Expiration & Aging Policies (/etc/login.defs)"
    if [[ -f /etc/login.defs ]]; then
        local def_max def_min def_warn def_umask def_enc
        def_max=$(login_def PASS_MAX_DAYS)
        def_min=$(login_def PASS_MIN_DAYS)
        def_warn=$(login_def PASS_WARN_AGE)
        def_umask=$(login_def UMASK)
        def_enc=$(login_def ENCRYPT_METHOD)

        echo -e "  /etc/login.defs Default Policies:"
        echo -e "    - PASS_MAX_DAYS : ${CYAN}${def_max:-99999}${NC}"
        echo -e "    - PASS_MIN_DAYS : ${CYAN}${def_min:-0}${NC}"
        echo -e "    - PASS_WARN_AGE : ${CYAN}${def_warn:-7}${NC}"
        echo -e "    - UMASK         : ${CYAN}${def_umask:-022 (not set, default)}${NC}"
        echo -e "    - ENCRYPT_METHOD: ${CYAN}${def_enc:-YESCRYPT}${NC}"

        if [[ -z "$def_max" || "$def_max" -ge 99999 ]]; then
            log_info "PASS_MAX_DAYS=${def_max:-99999} (no forced password rotation). This matches NIST SP 800-63B (no periodic rotation); set limits only if your policy demands it."
        else
            log_pass "System PASS_MAX_DAYS policy verified (${def_max} days)."
        fi
        if [[ "${def_min:-0}" -eq 0 ]]; then
            log_info "PASS_MIN_DAYS=0 (password may be changed repeatedly). Only relevant if you enforce password history/rotation."
        fi

        local umask_eff="${def_umask:-022}"
        if [[ "$umask_eff" =~ ^0?(022|002|000)$ ]]; then
            log_warn "Effective default UMASK is ${umask_eff} (new files readable by group/others). Recommended: 027 or 077."
        else
            log_pass "Default system UMASK policy verified (${umask_eff})."
        fi
        if [[ "$def_enc" =~ DES|MD5 ]]; then
            log_crit "Obsolete & insecure password encryption method '${def_enc}' in /etc/login.defs! Upgrade to SHA512 or YESCRYPT."
        fi
    fi
}

audit_sudoers() {
    subsection "Sudoers Hardening & NOPASSWD Audit"
    # /etc/sudoers permissions are covered by the filesystem matrix; drop-ins are checked here
    local files=(/etc/sudoers) sf mode
    while read -r sf; do files+=("$sf"); done < <(find /etc/sudoers.d -type f 2>/dev/null)

    local nopasswd=() gtfobins=() env_keep=() hits
    local gtfobins_re="find|vim|vi|less|more|nmap|python|python3|perl|php|awk|bash|sh|env|gdb|strace|tcpdump"
    for sf in "${files[@]}"; do
        [[ -r "$sf" ]] || continue
        if [[ "$sf" != "/etc/sudoers" ]]; then
            mode=$(file_mode "$sf")
            if [[ "$mode" =~ ^(440|400)$ ]]; then
                log_pass "${sf}: Permissions secure (${mode} $(stat -c %U:%G "$sf"))"
            else
                log_warn "${sf}: Non-standard permissions (${mode} $(stat -c %U:%G "$sf")). Recommended: 440"
            fi
        fi
        hits=$(grep -Ei "NOPASSWD[[:space:]]*:" "$sf" 2>/dev/null | grep -v '^[[:space:]]*#')
        [[ -n "$hits" ]] && nopasswd+=("${sf}:\n${hits}")
        hits=$(grep -Ei "NOPASSWD.*\b(${gtfobins_re})\b" "$sf" 2>/dev/null | grep -v '^[[:space:]]*#')
        [[ -n "$hits" ]] && gtfobins+=("${sf}:\n${hits}")
        hits=$(grep -Ei "env_keep.*\b(LD_PRELOAD|PATH|PYTHONPATH|PERL5LIB)\b" "$sf" 2>/dev/null | grep -v '^[[:space:]]*#')
        [[ -n "$hits" ]] && env_keep+=("${sf}: ${hits}")
    done

    if [[ ${#nopasswd[@]} -gt 0 ]]; then
        log_warn "NOPASSWD privilege escalation rules found in sudoers:\n$(printf '%b\n' "${nopasswd[@]}")"
    else
        log_pass "No NOPASSWD directives found in readable sudoers configuration."
    fi
    [[ ${#gtfobins[@]} -gt 0 ]] && log_crit "Dangerous GTFOBins binaries (find/vim/bash/python/nmap) allowed in NOPASSWD sudoers rules!\n$(printf '%b\n' "${gtfobins[@]}")"
    [[ ${#env_keep[@]} -gt 0 ]] && log_crit "Dangerous env_keep settings (LD_PRELOAD/PATH) in sudoers! Allows arbitrary library injection during sudo execution:\n$(printf '%s\n' "${env_keep[@]}")"
}

audit_pam() {
    subsection "PAM Authentication Stack Audit (/etc/pam.d/*)"
    [[ -d /etc/pam.d ]] || return 0
    local permit exec_hooks foreign
    permit=$(grep -Ei "^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_permit\.so" /etc/pam.d/* 2>/dev/null)
    if [[ -n "$permit" ]]; then
        log_crit "Bypassed authentication found in PAM stack (pam_permit.so sufficient):\n$permit"
    else
        log_pass "PAM authentication stack verified (No unconditional pam_permit bypasses)."
    fi

    exec_hooks=$(grep -Ei "pam_exec\.so" /etc/pam.d/* 2>/dev/null | grep -v ':[[:space:]]*#')
    if [[ -n "$exec_hooks" ]]; then
        log_warn "PAM exec module (pam_exec.so) detected in auth stack (Potential keylogging/hook):\n$exec_hooks"
    else
        log_pass "No pam_exec.so hooks detected in PAM configuration."
    fi

    foreign=$(grep -Ei "\.so" /etc/pam.d/* 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/|/home/")
    [[ -n "$foreign" ]] && log_crit "UNAUTHORIZED PAM MODULE: PAM configuration loads module from temporary/user directory:\n$foreign"
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

# --- Packages: repositories, kernel, recommended packages -----------------------
audit_repositories() {
    subsection "Configured Package Repositories (Official vs Unofficial/Third-Party)"
    local total=0 unofficial=0 findings=""

    if [[ "$PKG_MGR" == "apt" ]]; then
        local files=() sf line url domain
        [[ -f /etc/apt/sources.list ]] && files+=(/etc/apt/sources.list)
        while read -r sf; do files+=("$sf"); done < <(find /etc/apt/sources.list.d -type f \( -name "*.list" -o -name "*.sources" \) 2>/dev/null | sort)
        echo -e "${CYAN}Discovered APT Repositories (${#files[@]} config file(s)):${NC}"
        local official_re='(^|\.)(debian\.org|ubuntu\.com|kali\.org|raspbian\.org|linuxmint\.com)$'

        # One-line "deb URL ..." entries and deb822 "URIs: URL [URL...]" fields
        [[ ${#files[@]} -gt 0 ]] && while read -r url; do
            total=$((total + 1))
            domain=$(awk -F/ '{print $3}' <<< "$url")
            if [[ "$domain" =~ $official_re ]]; then
                echo -e "  [${GREEN}OFFICIAL${NC}] ${CYAN}${domain}${NC} -> ${url}"
            else
                unofficial=$((unofficial + 1))
                echo -e "  [${RED}UNOFFICIAL / THIRD-PARTY${NC}] ${YELLOW}${domain}${NC} -> ${url}"
                findings+="  - Unofficial Repo (${domain}): ${url}\n"
            fi
        done < <(cat "${files[@]}" 2>/dev/null \
                 | grep -E '^[[:space:]]*(deb|deb-src)[[:space:]]|^[[:space:]]*URIs:' \
                 | grep -oE '(https?|ftp)://[^ "]+' | sort -u)
    elif [[ "$PKG_MGR" == "dnf" ]]; then
        echo -e "${CYAN}Discovered DNF/YUM Repositories (/etc/yum.repos.d/*.repo):${NC}"
        local official_re='fedoraproject\.org|redhat\.com|centos\.org|almalinux\.org|rockylinux\.org'
        local rfile repo_id base_url enabled domain
        for rfile in /etc/yum.repos.d/*.repo; do
            [[ -f "$rfile" ]] || continue
            repo_id=$(basename "$rfile" .repo)
            base_url=$(grep -Ei '^[[:space:]]*(baseurl|metalink|mirrorlist)[[:space:]]*=' "$rfile" | head -n 1 | cut -d= -f2- | tr -d ' ')
            enabled=$(grep -Ei '^[[:space:]]*enabled[[:space:]]*=' "$rfile" | tail -n 1 | cut -d= -f2 | tr -d ' ')
            [[ "$enabled" == "0" ]] && continue
            total=$((total + 1))
            domain=$(awk -F/ '{print $3}' <<< "$base_url")
            if [[ "${domain:-$repo_id}" =~ $official_re ]]; then
                echo -e "  [${GREEN}OFFICIAL${NC}] ${CYAN}${repo_id}${NC} -> ${base_url:-$rfile}"
            else
                unofficial=$((unofficial + 1))
                echo -e "  [${RED}UNOFFICIAL / THIRD-PARTY${NC}] ${YELLOW}${repo_id}${NC} -> ${base_url:-$rfile}"
                findings+="  - Unofficial DNF Repo (${repo_id}): ${base_url:-$rfile}\n"
            fi
        done
    fi

    if [[ "$unofficial" -gt 0 ]]; then
        log_warn "Discovered ${unofficial} unofficial/third-party package repositories:\n$findings"
    else
        log_pass "Repository audit completed: All ${total} configured package repositories belong to official distribution sources."
    fi
}

audit_kernel_packages() {
    subsection "Kernel Updates & Reboot Status"
    local running kernel_updates
    running=$(uname -r)
    echo -e "Current running kernel: ${CYAN}${running}${NC} (package manager: ${PKG_MGR:-none})"

    case "$PKG_MGR" in
        apt) kernel_updates=$(pkg_upgrades | awk -F'\t' '$1 ~ /^linux-(image|headers|generic|amd64|arm64)/ {print $1}') ;;
        dnf) kernel_updates=$(pkg_upgrades | awk -F'\t' '$1 ~ /^kernel(-core|-modules)?$/ {print $1}') ;;
    esac
    if [[ -n "$kernel_updates" ]]; then
        log_warn "New kernel update available in repository (install it and reboot):\n$kernel_updates"
    elif [[ -n "$PKG_MGR" ]]; then
        log_pass "Kernel is up to date in repository."
    fi

    if [[ -f /var/run/reboot-required ]]; then
        log_warn "System reboot required! (/var/run/reboot-required exists)"
        [[ -f /var/run/reboot-required.pkgs ]] && sed 's/^/  - /' /var/run/reboot-required.pkgs
    elif [[ "$PKG_MGR" == "dnf" ]]; then
        local newest
        newest=$(rpm -q kernel-core --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V | tail -n 1)
        if [[ -n "$newest" && "$running" != "$newest"* ]]; then
            log_warn "System reboot required! Running kernel (${running}) differs from the newest installed (${newest})."
        fi
    fi
}

audit_recommended_packages() {
    subsection "Recommended Security Packages"
    local recommended pkg
    case "$PKG_MGR" in
        apt)
            recommended=(ufw auditd apparmor unattended-upgrades clamav chkrootkit needrestart debsums lynis)
            # fail2ban only makes sense when an SSH daemon is installed
            [[ -f /etc/ssh/sshd_config ]] && recommended+=(fail2ban)
            ;;
        dnf) recommended=(fail2ban firewalld audit clamav chkrootkit trivy policycoreutils crypto-policies) ;;
        *)   echo -e "${YELLOW}Unsupported package manager. Skipping recommended package audit.${NC}"; return 0 ;;
    esac
    local upgradable
    upgradable=$(pkg_upgrades | cut -f1)
    for pkg in "${recommended[@]}"; do
        if ! pkg_installed "$pkg"; then
            echo -e "  - ${pkg}: ${YELLOW}Not installed${NC} (Recommended for security)"
        elif grep -qxF "$pkg" <<< "$upgradable"; then
            echo -e "  - ${pkg}: ${GREEN}Installed${NC} | ${RED}Update Available in Repo${NC}"
        else
            echo -e "  - ${pkg}: ${GREEN}Installed (Up to date)${NC}"
        fi
    done

    if have needrestart; then
        step "Needrestart Check (Services needing restart after package updates):"
        local svcs svc
        svcs=$(needrestart -b 2>/dev/null | awk '/^NEEDRESTART-SVC:/ {print $2}')
        if [[ -z "$svcs" ]]; then
            echo -e "${GREEN}[OK] No background services require restart.${NC}"
        else
            log_warn "Background services require restart due to updated binaries/libraries:\n$svcs"
            if [[ "$AUTO_RESTART_SERVICES" == true ]]; then
                echo -e "${YELLOW}Auto-restarting outdated background services...${NC}"
                while read -r svc; do
                    restart_service "$svc" "outdated binary/library after package update"
                done <<< "$svcs"
            else
                echo -e "${YELLOW}Tip: run with --restart-services to auto-restart outdated services.${NC}"
            fi
        fi
    fi
}

audit_pinned_packages() {
    subsection "Pinned / Held Package Versions & Repo Candidates"
    local pins="" pkg inst cand count=0

    if [[ "$PKG_MGR" == "apt" ]]; then
        pins=$( { apt-mark showhold 2>/dev/null
                  dpkg --get-selections 2>/dev/null | awk '$2 == "hold" {print $1}'
                  grep -hEi "^[[:space:]]*Package:" /etc/apt/preferences /etc/apt/preferences.d/* 2>/dev/null | awk '{print $2}' | grep -v '\*'
                } | sed '/^[[:space:]]*$/d' | sort -u)
        [[ -n "$pins" ]] && echo -e "${CYAN}Discovered Pinned / Held Packages in APT Preferences & Database:${NC}"
        while read -r pkg; do
            [[ -n "$pkg" ]] || continue
            count=$((count + 1))
            local policy
            policy=$(apt-cache policy "$pkg" 2>/dev/null)
            inst=$(awk '/Installed:/ {print $2; exit}' <<< "$policy")
            cand=$(awk '/Candidate:/ {print $2; exit}' <<< "$policy")
            echo -e "  - Package: ${CYAN}${pkg}${NC}"
            echo -e "    Installed (Pinned): ${YELLOW}${inst:-Not Installed}${NC} | Latest Candidate in Repo: ${GREEN}${cand:-Unknown}${NC}"
            if [[ -n "$cand" && "$inst" != "$cand" ]]; then
                log_warn "Pinned package '${pkg}' (${inst:-not installed}) has a newer candidate version in repository (${cand})."
            else
                log_pass "Pinned package '${pkg}' (${inst}) is up-to-date with repository candidate."
            fi
        done <<< "$pins"
    elif [[ "$PKG_MGR" == "dnf" && -f /etc/dnf/plugins/versionlock.list ]]; then
        pins=$(grep -v '^[[:space:]]*#' /etc/dnf/plugins/versionlock.list | sed -E 's/^[0-9]+://; s/-[0-9].*$//' | sed '/^$/d' | sort -u)
        [[ -n "$pins" ]] && echo -e "${CYAN}Discovered Locked Packages in DNF Versionlock:${NC}"
        while read -r pkg; do
            [[ -n "$pkg" ]] || continue
            count=$((count + 1))
            inst=$(rpm -q --queryformat '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null)
            cand=$(pkg_upgrades | awk -F'\t' -v p="$pkg" '$1 == p {split($2, a, " "); print a[1]; exit}')
            echo -e "  - Package: ${CYAN}${pkg}${NC}"
            echo -e "    Installed (Pinned): ${YELLOW}${inst:-Not Installed}${NC} | Latest Candidate in Repo: ${GREEN}${cand:-${inst} (Up-to-date)}${NC}"
            if [[ -n "$cand" ]]; then
                log_warn "Pinned package '${pkg}' (${inst}) has a newer version available in repository (${cand})."
            else
                log_pass "Pinned package '${pkg}' (${inst}) is up-to-date with repository."
            fi
        done <<< "$pins"
    fi

    [[ "$count" -eq 0 ]] && log_pass "No pinned or held package versions detected in system package manager."
}

section_packages() {
    audit_repositories
    audit_kernel_packages
    audit_recommended_packages
    audit_pinned_packages
}

# --- Pending updates ------------------------------------------------------------
section_updates() {
    subsection "Pending Package Updates (Security & Total)"
    if [[ -z "$PKG_MGR" ]]; then
        echo -e "  ${YELLOW}No supported package manager found for update counting.${NC}"
    else
        local names total security key_apps="" app
        names=$(pkg_upgrades | cut -f1)
        total=$(grep -c . <<< "$names")
        security=$(pkg_security_upgrades | grep -c .)
        for app in "${KEY_APPS[@]}"; do
            grep -qxF "$app" <<< "$names" && key_apps+="${app} "
        done
        echo -e "  Total packages awaiting update : ${CYAN}${total}${NC}"
        echo -e "  Security updates pending        : ${CYAN}${security}${NC}"
        [[ -n "$key_apps" ]] && echo -e "  Key applications with updates   : ${CYAN}${key_apps}${NC}"

        if [[ "$security" -gt 0 ]]; then
            log_crit "${security} SECURITY update(s) are pending installation! Known CVEs are exploitable until patched. Run the package manager update immediately."
        elif [[ "$total" -gt 0 ]]; then
            log_warn "${total} package update(s) available (no security updates among them). Regular patching is recommended."
        else
            log_pass "All installed packages are up to date."
        fi
    fi

    subsection "Automatic Security Updates Status"
    if [[ "$PKG_MGR" == "apt" ]]; then
        if unit_active unattended-upgrades; then
            log_pass "unattended-upgrades service is active: automatic security updates enabled."
        elif grep -qE 'APT::Periodic::Unattended-Upgrade[[:space:]]+"1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
            log_pass "unattended-upgrades is configured (APT::Periodic::Unattended-Upgrade=1)."
        elif unit_exists apt-daily-upgrade.timer; then
            log_warn "apt-daily-upgrade timer exists but unattended-upgrades package/config is not enabled. Automatic SECURITY updates are likely NOT active."
        else
            log_warn "Automatic security updates are NOT configured. Install & enable 'unattended-upgrades' for timely CVE patching."
        fi
    elif [[ "$PKG_MGR" == "dnf" ]]; then
        if unit_active dnf-automatic.timer || unit_active dnf-automatic-install.timer || unit_active dnf5-automatic.timer; then
            log_pass "dnf-automatic timer is active: automatic updates enabled."
        elif grep -qE '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*(yes|true|1)' /etc/dnf/automatic.conf 2>/dev/null; then
            log_pass "dnf-automatic is configured with apply_updates=yes."
        else
            log_warn "Automatic updates (dnf-automatic) are NOT configured. Security patches will only apply on manual 'dnf update'."
        fi
    fi
}

# --- Processes ------------------------------------------------------------------
section_processes() {
    # One snapshot for all pattern checks (no grep processes of our own in it)
    local snapshot
    snapshot=$(ps -eo user,pid,args 2>/dev/null | grep -v "system-audit")

    subsection "1. Processes Executing from Temporary Directories (/tmp, /var/tmp, /dev/shm)"
    local exe target pid temp_procs=""
    for exe in /proc/[0-9]*/exe; do
        target=$(readlink "$exe" 2>/dev/null)
        [[ "$target" =~ ^(/tmp/|/var/tmp/|/dev/shm/) ]] || continue
        pid=${exe#/proc/}; pid=${pid%/exe}
        temp_procs+="PID ${pid} (User: $(ps -o user= -p "$pid" 2>/dev/null)) -> ${target} [Cmd: $(tr '\0' ' ' 2>/dev/null < "/proc/$pid/cmdline")]\n"
    done
    if [[ -n "$temp_procs" ]]; then
        log_warn "Processes running from temporary/volatile directories found:\n$temp_procs"
    else
        log_pass "No processes executing from /tmp, /var/tmp, or /dev/shm."
    fi

    subsection "2. Known Miner & Suspicious Tool Signatures"
    local hits
    hits=$(grep -Ei "xmrig|minerd|cgminer|cpuminer|kworkerds|stratum|masscan|zmap|kinsing|sysupdate" <<< "$snapshot")
    if [[ -n "$hits" ]]; then
        log_crit "Known suspicious miner or scanning tools detected:\n$hits"
    else
        log_pass "No known miner or scanning tool signatures detected."
    fi

    subsection "3. Potential Reverse Shell Patterns"
    hits=$(grep -Ei "nc -e|nc\.openbsd -e|bash -i|sh -i|python.*socket|perl.*socket|php -r.*socket" <<< "$snapshot")
    if [[ -n "$hits" ]]; then
        log_crit "Potential reverse shell processes detected:\n$hits"
    else
        log_pass "No reverse shell command patterns detected."
    fi

    subsection "4. Zombie & Orphan Processes"
    local zpid zppid zuser zcomm parent zombies
    zombies=$(ps -eo pid=,ppid=,user=,stat=,comm= 2>/dev/null | awk '$4 ~ /^Z/ {print $1, $2, $3, $5}')
    if [[ -n "$zombies" ]]; then
        echo -e "${CYAN}Discovered Zombie (Defunct) Processes:${NC}"
        while read -r zpid zppid zuser zcomm; do
            parent=$(ps -o comm= -p "$zppid" 2>/dev/null)
            log_warn "ZOMBIE PROCESS: PID ${zpid} (Name: '${zcomm}', User: ${zuser}) | Parent PPID ${zppid} (Name: '${parent:-Unknown}')"
            echo "  Note: a zombie is already dead; only its parent (PPID ${zppid}, '${parent:-Unknown}') can reap it. Restart that parent if the zombie persists. (This script never kills processes.)"
        done <<< "$zombies"
    else
        log_pass "No Zombie (defunct) processes detected."
    fi

    # Orphans: re-parented to PID 1, owned by a normal user, running a binary OUTSIDE
    # package-managed locations (desktop daemons under /usr or /opt are normal)
    step "Auditing Orphan Processes (PPID=1, non-root) running from non-system locations:"
    local opid ouser oexe orphans=""
    while read -r opid ouser; do
        oexe=$(readlink "/proc/$opid/exe" 2>/dev/null)
        case "$oexe" in
            ""|/usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/opt/*|/snap/*|/nix/store/*) continue ;;
        esac
        orphans+="PID ${opid} (User: ${ouser}) -> ${oexe}\n"
    done < <(ps -eo pid=,ppid=,user= 2>/dev/null | awk '$2 == 1 && $1 != 1 && $3 != "root" {print $1, $3}')
    if [[ -n "$orphans" ]]; then
        log_warn "Orphan processes (PPID=1) running binaries from non-system locations:\n$orphans"
    else
        log_pass "No suspicious orphan processes (PPID=1 outside package-managed paths)."
    fi

    subsection "5. Top CPU & RAM Consuming Processes"
    echo -e "${CYAN}Highest CPU Processes (>70% CPU):${NC}"
    local high_cpu
    # ps %cpu is a lifetime average (a just-started 'ps' reports 100%), so sample 1s with top instead
    high_cpu=$(top -b -n 2 -d 1 -w 512 2>/dev/null | awk '/^top -/ {frame++} frame == 2 && $1 ~ /^[0-9]+$/ && $9 + 0 > 70.0 && $12 != "top" {printf "  %s %s %s%% CPU %s%% MEM %s\n", $1, $2, $9, $10, $12}')
    if [[ -n "$high_cpu" ]]; then
        log_warn "Processes consuming high CPU (>70%):\n$high_cpu"
    else
        log_pass "No processes consuming excessive CPU (>70%)."
    fi
    echo -e "${CYAN}Highest RAM Consuming Processes (Top 5):${NC}"
    ps -eo pid,user,%cpu,%mem,comm --sort=-%mem | head -n 6
}

# --- Shell config files & $PATH -------------------------------------------------
section_shell_configs() {
    local rc_names=(.bashrc .zshrc .profile .bash_profile .zprofile .bash_aliases .zsh_aliases)
    local hijack_re="alias (sudo|su|ssh|cd|ls|cat|curl|wget)="
    local exec_re="curl.*\|.*(bash|sh)|wget.*\|.*(bash|sh)|eval \\\$\(|base64 -d"
    local user uid home shell rc rc_files findings hits cmd

    while IFS=: read -r user uid home shell; do
        [[ -d "$home" ]] || continue
        rc_files=()
        for rc in "${rc_names[@]}"; do
            [[ -f "$home/$rc" ]] && rc_files+=("$home/$rc")
        done
        [[ ${#rc_files[@]} -gt 0 ]] || continue

        echo -e "\n${CYAN}--- User '${user}' Shell Configuration Audit (${rc_files[*]}) ---${NC}"
        findings=""
        for rc in "${rc_files[@]}"; do
            hits=$(grep -Ei "$hijack_re" "$rc" 2>/dev/null | grep -vE '^[[:space:]]*#' | grep -vE "alias ls='ls --color|alias ll=|alias la=")
            [[ -n "$hits" ]] && findings+="Suspicious alias in ${rc}:\n${hits}\n"
            hits=$(grep -Ei "$exec_re" "$rc" 2>/dev/null | grep -vE '^[[:space:]]*#')
            [[ -n "$hits" ]] && findings+="Dangerous execution pattern in ${rc}:\n${hits}\n"
        done
        if [[ -n "$findings" ]]; then
            log_warn "Suspicious aliases or remote execution patterns detected for ${user}:\n${findings}"
        else
            log_pass "No suspicious alias hijacking or remote code execution patterns found for ${user}."
        fi

        echo -e "${YELLOW}Safety Aliases & Protection Recommendations for ${user}:${NC}"
        for cmd in rm cp mv; do
            if grep -Eqs "alias ${cmd}=['\"].*${cmd}.*-i" "${rc_files[@]}"; then
                echo -e "  - '${cmd}' safety alias: ${GREEN}Enabled${NC}"
            else
                log_warn "Missing '${cmd}' safety alias for ${user} -> Add alias ${cmd}='${cmd} -i' to ${rc_files[0]}"
            fi
        done
    done < <(all_accounts)

    subsection "Auditing System \$PATH Environment Directories for Binary Hijacking Risk"
    # The PATH this audit was started with (sudo's secure_path), not the one extended at the top
    local dirs dir mode owner path_issues=0
    IFS=':' read -ra dirs <<< "$ORIGINAL_PATH"
    for dir in "${dirs[@]}"; do
        if [[ -z "$dir" || "$dir" == "." ]]; then
            log_crit "DANGEROUS \$PATH ENTRY: Current directory '.' or empty entry found in \$PATH! Vulnerable to local binary hijacking."
            path_issues=$((path_issues + 1))
            continue
        fi
        if [[ ! -d "$dir" ]]; then
            log_warn "\$PATH directory '${dir}' does not exist."
            path_issues=$((path_issues + 1))
            continue
        fi
        mode=$(file_mode "$dir")
        owner=$(stat -L -c %U "$dir" 2>/dev/null)
        if mode_has "$mode" 002; then
            log_crit "WORLD-WRITABLE \$PATH DIRECTORY: '${dir}' (Target: '$(readlink -f "$dir")', Mode: ${mode}, Owner: ${owner})! Unprivileged users can drop malicious binaries to hijack root/user commands."
            path_issues=$((path_issues + 1))
        elif [[ "$owner" != "root" ]]; then
            log_warn "\$PATH directory '${dir}' is owned by non-root user '${owner}' (Mode: ${mode})."
            path_issues=$((path_issues + 1))
        else
            echo -e "  - \$PATH Directory ${CYAN}${dir}${NC}: ${GREEN}Secure permissions (${mode}, Owner: ${owner})${NC}"
        fi
    done
    [[ "$path_issues" -eq 0 ]] && log_pass "All directories in system \$PATH are secure, non-world-writable, and owned by root."
}

# --- SUID / SGID ----------------------------------------------------------------
section_suid() {
    subsection "SUID/SGID Binaries in Volatile & Non-Standard Paths"
    local found sfile owner_pkg pkg_owned="" unowned=""
    found=$(find /tmp /var/tmp /dev/shm /home /opt /var/www /srv -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    if [[ -z "$found" ]]; then
        log_pass "No SUID/SGID files found in volatile or user paths (/tmp, /dev/shm, /home, /opt, /var/www)."
    else
        while read -r sfile; do
            owner_pkg=$(pkg_owner "$sfile")
            if [[ -n "$owner_pkg" ]]; then
                pkg_owned+="  - ${sfile}  (shipped by package: ${owner_pkg})\n"
            else
                unowned+="  - ${sfile}\n"
            fi
        done <<< "$found"
        [[ -n "$pkg_owned" ]] && log_info "SUID/SGID helpers installed by packages outside /usr (expected, e.g. the Chrome/Electron sandbox):\n$pkg_owned"
        if [[ -n "$unowned" ]]; then
            log_crit "SUID/SGID files NOT owned by any package in volatile / user / web paths:\n$unowned"
        else
            log_pass "No unowned SUID/SGID files in volatile or user paths (package-owned helpers listed above are expected)."
        fi
    fi

    subsection "System-Wide SUID Binaries & GTFOBins Privilege Escalation Risk"
    local suid_files gtfobins
    suid_files=$(find /usr/bin /usr/sbin /bin /sbin /usr/lib /usr/libexec -type f -perm -4000 2>/dev/null | sort -u)
    echo -e "  Total SUID binaries in system paths: ${CYAN}$(grep -c . <<< "$suid_files")${NC}"
    local gtfobins_re='^(find|vim|vi|bash|sh|python|python3|perl|php|awk|less|more|nmap|env|gdb|strace|tcpdump|tar|cp|mv|base64|cpulimit|docker|date|dd|flock|ionice|nice|taskset|time|timeout|watch|xargs|zip|zsh)$'
    gtfobins=$(while read -r sfile; do [[ -n "$sfile" && "${sfile##*/}" =~ $gtfobins_re ]] && echo "  - $sfile"; done <<< "$suid_files")
    if [[ -n "$gtfobins" ]]; then
        log_crit "DANGEROUS SUID GTFOBINS BINARIES DETECTED:\n${gtfobins}\nThese SUID binaries allow immediate local privilege escalation to root shell!"
    else
        log_pass "No GTFOBins privilege escalation binaries have SUID flags enabled."
    fi

    subsection "World-Writable System Files Audit"
    local ww_files
    ww_files=$(find /etc /var /opt /usr /boot -type f -perm -0002 2>/dev/null | head -n 20)
    if [[ -n "$ww_files" ]]; then
        log_crit "WORLD-WRITABLE FILES DETECTED in system paths:\n$(sed 's/^/  - /' <<< "$ww_files")\nAny unprivileged user can modify or replace these files!"
    else
        log_pass "No world-writable files found in system directories (/etc, /var, /usr, /opt, /boot)."
    fi
}

# --- Persistence: cron, timers, at ----------------------------------------------
section_persistence() {
    # Download-and-execute, reverse shells, encoded payloads, staging dirs. Plain `eval`,
    # `nohup` or /tmp usage is common in legitimate package cron scripts.
    local suspicious_re='(curl|wget)[^|#]*\|[[:space:]]*(ba|z)?sh|/dev/tcp/|base64[[:space:]]+(-d|--decode)|(^|[[:space:]=])/(dev/shm|var/tmp)/|python[0-9.]*[[:space:]]+-c|nc[[:space:]]+-e|chmod[[:space:]]+[0-7]*777'
    local flagged=0 user uid home shell jobs hits

    subsection "User Cron Jobs"
    while IFS=: read -r user uid home shell; do
        jobs=$(crontab -u "$user" -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
        [[ -n "$jobs" ]] || continue
        echo -e "${CYAN}Crontab for user '${user}':${NC}"
        echo "$jobs"
        hits=$(grep -E "$suspicious_re" <<< "$jobs" | head -n 5)
        if [[ -n "$hits" ]]; then
            log_crit "SUSPICIOUS CRON TASK for user '${user}':\n$hits"
            flagged=$((flagged + 1))
        fi
    done < <(all_accounts)

    subsection "System Cron Files (/etc/crontab, /etc/cron.*)"
    if [[ -f /etc/crontab ]]; then
        grep -vE '^[[:space:]]*(#|$)' /etc/crontab || echo "No custom jobs in /etc/crontab."
    fi
    local cfile
    while read -r cfile; do
        hits=$(grep -E "$suspicious_re" "$cfile" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n 5)
        [[ -n "$hits" ]] || continue
        flagged=$((flagged + 1))
        if [[ -n "$(pkg_owner "$cfile")" ]]; then
            log_warn "Package-owned cron file ${cfile} matches a suspicious pattern (verify with: debsums -c):\n$hits"
        else
            log_crit "SUSPICIOUS CRON TASK in ${cfile} (download/decode/obfuscation patterns):\n$hits"
        fi
    done < <(find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -type f 2>/dev/null; [[ -f /etc/crontab ]] && echo /etc/crontab)

    subsection "Systemd Timers"
    if have systemctl; then
        systemctl list-timers --no-pager --no-legend 2>/dev/null | head -n 10
        # The command a timer runs lives in the unit it activates
        local timer unit exec_path
        while read -r timer; do
            unit=$(systemctl show -P Unit "$timer" 2>/dev/null)
            [[ -n "$unit" ]] || continue
            while read -r exec_path; do
                if [[ "$exec_path" =~ ^(/tmp|/dev/shm|/var/tmp)/ ]]; then
                    log_crit "systemd timer '${timer}' executes from a temporary directory: ${exec_path}"
                    flagged=$((flagged + 1))
                elif [[ -f "$exec_path" ]] && mode_has "$(file_mode "$exec_path")" 022; then
                    log_warn "systemd timer '${timer}' executes a group/world-writable binary: ${exec_path} ($(file_mode "$exec_path"))"
                    flagged=$((flagged + 1))
                fi
            done < <(systemctl show -P ExecStart "$unit" 2>/dev/null | grep -oE 'path=[^ ;]+' | cut -d= -f2)
        done < <(systemctl list-units --type=timer --all --no-legend --plain 2>/dev/null | awk '{print $1}')
    fi

    if have atq; then
        local at_jobs
        at_jobs=$(atq 2>/dev/null | head -n 5)
        [[ -n "$at_jobs" ]] && echo -e "  Pending 'at' jobs:\n$at_jobs"
    fi

    if [[ "$flagged" -eq 0 ]]; then
        log_pass "No suspicious scheduled tasks (cron/systemd-timers) detected."
    fi
}

# --- SSH authorized_keys --------------------------------------------------------
section_authorized_keys() {
    subsection "Auditing SSH Authorized Keys Across All System Accounts"
    local keys_count=0 user uid home shell auth_file mode is_admin line fields field ktype comment

    while IFS=: read -r user uid home shell; do
        for auth_file in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [[ -f "$auth_file" ]] || continue
            is_admin=false
            if [[ "$uid" -eq 0 ]] || user_is_admin "$user"; then
                is_admin=true
            fi
            # Public keys may be world-readable; group/world WRITE lets others add their keys
            mode=$(file_mode "$auth_file")
            if mode_has "$mode" 022; then
                log_crit "User '${user}': Loose permissions on ${auth_file} (${mode})! File is writable by group or others. Recommended: 600."
            fi

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

                if [[ "$is_admin" == true ]]; then
                    if [[ "$line" == *"from="* ]]; then
                        log_pass "User '${user}': Authorized key '${comment}' is IP-restricted ($(grep -o 'from="[^"]*"' <<< "$line"))."
                    else
                        log_warn "User '${user}' (Administrative Account): Authorized key '${comment}' has NO 'from=\"IP\"' restriction! Key can connect from any remote host."
                    fi
                fi

                case "$ktype" in
                    ssh-dss)
                        log_crit "User '${user}': Obsolete & insecure DSA key in ${auth_file} ('${comment}')! DSA 1024-bit keys are cryptographically broken." ;;
                    ssh-rsa)
                        echo -e "    - User ${CYAN}${user}${NC}: RSA Key ('${comment:-no comment}')" ;;
                    ssh-ed25519|sk-ssh-ed25519*)
                        echo -e "    - User ${CYAN}${user}${NC}: ${GREEN}Ed25519 Key${NC} ('${comment:-no comment}')" ;;
                    ecdsa-sha2-*|sk-ecdsa-*)
                        echo -e "    - User ${CYAN}${user}${NC}: ${GREEN}ECDSA Key${NC} ('${comment:-no comment}')" ;;
                esac
            done < "$auth_file"
        done
    done < <(all_accounts)

    if [[ -f /etc/ssh/authorized_keys ]]; then
        local global_cnt
        global_cnt=$(grep -cvE '^[[:space:]]*(#|$)' /etc/ssh/authorized_keys)
        [[ "$global_cnt" -gt 0 ]] && log_warn "Global SSH authorized_keys file detected (/etc/ssh/authorized_keys) containing ${global_cnt} key(s)."
    fi

    if [[ "$keys_count" -eq 0 ]]; then
        log_pass "No SSH authorized_keys files found across system user accounts."
    else
        log_pass "Audited ${keys_count} SSH authorized key(s) across all system users."
    fi
}

# --- Containers -----------------------------------------------------------------
section_containers() {
    if [[ -S /var/run/docker.sock ]]; then
        echo -e "Docker socket status: ${CYAN}$(ls -l /var/run/docker.sock 2>/dev/null)${NC}"
    else
        echo "Docker socket (/var/run/docker.sock) not active."
    fi

    if have docker && docker ps &>/dev/null; then
        subsection "Running Docker Containers"
        local privileged
        privileged=$(docker ps --quiet | xargs -r docker inspect --format '{{ .Name }} ({{ .Id }}): Privileged={{ .HostConfig.Privileged }}' 2>/dev/null | grep 'Privileged=true')
        if [[ -n "$privileged" ]]; then
            log_warn "Privileged containers detected:\n$privileged"
        else
            log_pass "No privileged Docker containers running."
        fi
    elif have podman && podman ps &>/dev/null; then
        subsection "Running Podman Containers"
        log_pass "Podman container daemon verified."
    fi
}

# --- Bootloader & kernel hardening ----------------------------------------------
# grub_setting KEY: value of KEY in /etc/default/grub, quotes removed
grub_setting() { grep -m1 "^$1=" /etc/default/grub 2>/dev/null | cut -d= -f2- | tr -d "\"'"; }

audit_grub() {
    subsection "Bootloader & GRUB Security Configuration Audit"
    local cfg found_cfg="" owner mode default_grub=/etc/default/grub
    for cfg in /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/efi/EFI/{debian,ubuntu,redhat,centos,fedora}/grub.cfg; do
        [[ -f "$cfg" ]] || continue
        found_cfg="$cfg"
        owner=$(stat -c "%U:%G" "$cfg" 2>/dev/null)
        mode=$(file_mode "$cfg")
        echo -e "  Found GRUB config file      : ${CYAN}${cfg}${NC} (Perms: ${mode}, Owner: ${owner})"
        [[ "$owner" == "root:root" || "$owner" == "root:wheel" ]] || log_warn "Insecure ownership on ${cfg}: owned by '${owner}' (Expected: root:root)."
        if [[ "$mode" =~ ^(600|700|400|440)$ ]]; then
            log_pass "GRUB config permissions verified (${cfg}: ${mode})."
        else
            log_warn "Insecure permissions on ${cfg} (${mode})! GRUB config is readable by non-root users. Recommended permissions: 600 or 700."
        fi
        break
    done
    if [[ -z "$found_cfg" ]]; then
        if [[ -d /sys/firmware/efi ]]; then
            echo -e "  ${YELLOW}No standard GRUB configuration file found. System may use systemd-boot or EFI stub.${NC}"
        else
            echo -e "  ${YELLOW}No GRUB configuration file found in standard /boot locations.${NC}"
        fi
    fi

    if [[ -f "$default_grub" ]]; then
        mode=$(file_mode "$default_grub")
        echo -e "  GRUB environment config     : ${CYAN}${default_grub}${NC} (Perms: ${mode}, Owner: $(stat -c "%U:%G" "$default_grub"))"
        if [[ "$mode" =~ ^(644|600|400)$ ]]; then
            log_pass "${default_grub} permissions verified (${mode})."
        else
            log_warn "Insecure permissions on ${default_grub} (${mode}). Recommended: 644 or 600."
        fi
    fi

    subsection "GRUB Password Protection & Bootloader Authentication Audit"
    if grep -qsE "password_pbkdf2|password " "$found_cfg" || grep -rqsE "password_pbkdf2|password " /etc/grub.d/; then
        log_pass "GRUB password protection is configured (PBKDF2/password protection active)."
    elif root_on_luks; then
        log_info "GRUB is not password protected, but / is on LUKS: an edited cmdline (init=/bin/bash) still needs the disk passphrase. Remaining risk: tampering with unencrypted /boot (mitigated by Secure Boot)."
    else
        log_warn "GRUB bootloader is NOT password protected! Users with physical or console access can modify boot options or gain root shell."
    fi

    subsection "GRUB Recovery Mode & Unauthenticated Boot Settings"
    if [[ -f "$default_grub" ]]; then
        local disable_rec root_pw timeout
        disable_rec=$(grub_setting GRUB_DISABLE_RECOVERY)
        if [[ "$disable_rec" == "true" || "$disable_rec" == "1" ]]; then
            log_pass "Unauthenticated GRUB recovery mode menu entries are disabled."
        else
            root_pw=$(passwd -S root 2>/dev/null | awk '{print $2}')
            if [[ "$root_pw" == "P" ]]; then
                log_info "GRUB recovery mode entries are enabled, but root has a password: recovery mode asks for it (sulogin). Real bypass is editing the kernel cmdline - see the GRUB password check above."
            else
                log_warn "GRUB recovery mode entries are enabled and root has no usable password (${root_pw:-unknown}): recovery mode may give a root shell without authentication."
            fi
        fi

        timeout=$(grub_setting GRUB_TIMEOUT)
        if [[ "$timeout" =~ ^-?[0-9]+$ ]]; then
            echo -e "  GRUB Menu Timeout           : ${CYAN}${timeout} second(s)${NC}"
            if [[ "$timeout" -eq -1 || "$timeout" -gt 10 ]]; then
                log_warn "GRUB_TIMEOUT is set to ${timeout}s (extended delay increases boot menu tampering window). Recommended: <= 5 seconds."
            else
                log_pass "GRUB boot menu timeout configuration verified (${timeout}s)."
            fi
        fi
    fi
}

audit_boot_state() {
    subsection "Active Kernel Boot Parameters Audit (/proc/cmdline)"
    local cmdline tok tokens
    cmdline=$(cat /proc/cmdline 2>/dev/null)
    echo -e "  Active Kernel Cmdline: ${CYAN}${cmdline}${NC}"
    read -ra tokens <<< "$cmdline"
    for tok in "${tokens[@]}"; do
        case "$tok" in
            init=/bin/bash|init=/bin/sh|rd.break|rd.break=*|emergency|systemd.unit=emergency.target)
                log_crit "DANGEROUS BOOT PARAMETER ACTIVE: '${tok}' in /proc/cmdline (root shell on boot)!" ;;
            single|s|S|1|systemd.unit=rescue.target)
                log_warn "Kernel booted in single-user / rescue mode (parameter '${tok}')." ;;
            selinux=0|enforcing=0|apparmor=0)
                log_warn "Mandatory Access Control framework disabled in kernel boot parameters ('${tok}')!" ;;
        esac
    done
    if [[ "$cmdline" =~ mitigations=off|noibrs|noibpb|nopti|nospectre_v1|nospectre_v2|nospec_store_bypass_disable ]]; then
        log_warn "CPU vulnerability mitigations disabled in kernel boot parameters!"
    else
        log_pass "CPU vulnerability mitigations are active in kernel parameters."
    fi
    if [[ " $cmdline " == *" audit=1 "* ]]; then
        log_pass "Kernel auditing parameter 'audit=1' is enabled."
    else
        echo -e "  ${YELLOW}Tip: Consider adding 'audit=1' to GRUB_CMDLINE_LINUX to enable early boot kernel auditing.${NC}"
    fi

    subsection "UEFI Secure Boot Status Audit"
    if have mokutil; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null)
        if [[ "$sb_state" == *"SecureBoot enabled"* ]]; then
            log_pass "UEFI Secure Boot is ENABLED."
        else
            log_warn "UEFI Secure Boot is DISABLED: ${sb_state}"
        fi
    elif [[ -d /sys/firmware/efi ]]; then
        local sb_var
        sb_var=$(find /sys/firmware/efi/efivars/ -name "SecureBoot-*" 2>/dev/null | head -n 1)
        if [[ -z "$sb_var" ]]; then
            echo -e "  UEFI firmware detected, but SecureBoot efivar status could not be read."
        elif [[ "$(od -An -t u1 "$sb_var" 2>/dev/null | awk '{print $NF}')" == "1" ]]; then
            log_pass "UEFI Secure Boot is ENABLED (via efivars)."
        else
            log_warn "UEFI Secure Boot is DISABLED (via efivars)."
        fi
    else
        echo -e "  Legacy BIOS system detected (UEFI Secure Boot not applicable)."
    fi
}

# check_sysctl PARAM EXPECTED
check_sysctl() {
    local val
    val=$(sysctl -n "$1" 2>/dev/null)
    if [[ "$val" == "$2" ]]; then
        log_pass "$1: ${val} (Secure)"
    else
        log_warn "$1: ${val} (Recommended: $2)"
    fi
}

audit_sysctl() {
    subsection "Kernel Hardening Parameters (sysctl)"
    if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "1" ]] && matches ': (virbr|docker)[0-9]' "$(ip -o link show 2>/dev/null)"; then
        log_info "net.ipv4.ip_forward=1 - required by libvirt/docker NAT networking (virbr*/docker* present). Fine on a workstation behind a NAT router."
    else
        check_sysctl net.ipv4.ip_forward 0
    fi
    check_sysctl kernel.kptr_restrict 1
    check_sysctl kernel.dmesg_restrict 1
    check_sysctl fs.protected_symlinks 1
    check_sysctl fs.protected_hardlinks 1
    check_sysctl fs.suid_dumpable 0

    local aslr ptrace syncookies ipv6_fwd
    aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
    echo -e "\n  ${CYAN}ASLR (kernel.randomize_va_space)  : ${aslr}${NC} (2=full randomization, 1=conservative, 0=DISABLED)"
    case "$aslr" in
        2) log_pass "kernel.randomize_va_space=2: Full ASLR enabled (mmap, heap, stack, VDSO randomized)." ;;
        1) log_warn "kernel.randomize_va_space=1: Conservative ASLR only (stack/mmap randomized, heap not). Recommended: 2." ;;
        *) log_crit "kernel.randomize_va_space=${aslr}: ASLR is DISABLED! Exploit mitigations (ROP/heap spraying) are ineffective." ;;
    esac

    ptrace=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)
    if [[ -n "$ptrace" ]]; then
        echo -e "  ${CYAN}ptrace_scope (kernel.yama)        : ${ptrace}${NC} (0=any process can ptrace, 1=restricted, 2=admin-only, 3=no attach)"
        if [[ "$ptrace" -ge 1 ]]; then
            log_pass "kernel.yama.ptrace_scope=${ptrace}: ptrace attach is restricted (Yama LSM active)."
        else
            log_warn "kernel.yama.ptrace_scope=0: any process with matching UID can ptrace others (credential/secret extraction via memory inspection). Recommended: >= 1."
        fi
    else
        echo -e "  ${YELLOW}kernel.yama.ptrace_scope not available (Yama LSM not built into this kernel).${NC}"
    fi

    syncookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
    echo -e "  ${CYAN}TCP SYN cookies                  : ${syncookies}${NC}"
    if [[ "$syncookies" == "1" ]]; then
        log_pass "net.ipv4.tcp_syncookies=1: SYN flood/DoS mitigation enabled."
    else
        log_warn "net.ipv4.tcp_syncookies=${syncookies}: SYN cookie protection is disabled. Recommended: 1."
    fi

    ipv6_fwd=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)
    if [[ -n "$ipv6_fwd" && "$ipv6_fwd" != "0" ]]; then
        log_warn "net.ipv6.conf.all.forwarding=${ipv6_fwd}: IPv6 forwarding is enabled on a non-router system."
    fi
}

audit_kernel_runtime() {
    subsection "Running Kernel & Uptime"
    # Pending kernel packages are reported in the 'packages' section
    echo -e "  Running Kernel Version       : ${CYAN}$(uname -r)${NC} ($(uname -v))"
    local uptime_days
    uptime_days=$(awk '{printf "%d", $1 / 86400}' /proc/uptime 2>/dev/null)
    if [[ "${uptime_days:-0}" -gt 90 ]]; then
        log_warn "System uptime is ${uptime_days} days: if kernel patches were installed without reboot, the running kernel may still expose patched CVEs (reboot required)."
    fi

    subsection "Core Dumps & Memory Leakage Hardening"
    local core_pattern
    core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
    echo -e "  System Core Pattern        : ${CYAN}${core_pattern:-default}${NC}"
    if [[ "$core_pattern" =~ ^(/tmp/|/var/tmp/|/dev/shm/) ]]; then
        log_crit "INSECURE CORE PATTERN: Core dumps write process memory to world-writable directory: ${core_pattern}!"
    else
        log_pass "Core dump pattern configuration verified."
    fi
}

section_boot_and_kernel() {
    audit_grub
    audit_boot_state
    audit_sysctl
    audit_kernel_runtime
}

# --- DNS ------------------------------------------------------------------------
section_dns() {
    subsection "DNS Resolvers & /etc/resolv.conf Integrity Audit"
    local resolv=/etc/resolv.conf
    if [[ -L "$resolv" ]]; then
        local target
        target=$(readlink -f "$resolv")
        echo -e "  /etc/resolv.conf mode      : ${CYAN}Symlink -> ${target}${NC}"
        log_pass "/etc/resolv.conf is managed dynamically via symlink (${target})."
    elif [[ -f "$resolv" ]]; then
        local mode
        mode=$(file_mode "$resolv")
        echo -e "  /etc/resolv.conf mode      : ${CYAN}Static File (Perms: ${mode}, Owner: $(stat -c %U:%G "$resolv"))${NC}"
        if [[ "$mode" =~ ^(644|600|400)$ ]]; then
            log_pass "/etc/resolv.conf file permissions verified (${mode})."
        else
            log_warn "Loose permissions on /etc/resolv.conf (${mode})! Non-root processes might modify DNS servers."
        fi
        if have lsattr && [[ "$(lsattr "$resolv" 2>/dev/null | awk '{print $1}')" == *i* ]]; then
            log_pass "/etc/resolv.conf has immutable attribute (+i) set against unauthorized tampering."
        fi
    else
        log_warn "/etc/resolv.conf file is missing!"
    fi

    if [[ -f "$resolv" ]]; then
        step "Configured Nameservers in /etc/resolv.conf:"
        local ns count=0 kind
        while read -r _ ns _; do
            [[ -n "$ns" ]] || continue
            count=$((count + 1))
            case "$ns" in
                127.*|::1)                    kind="Local Stub Resolver (systemd-resolved / dnsmasq)" ;;
                192.168.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) kind="Local Gateway / LAN Router DNS" ;;
                1.1.1.1|1.0.0.1)              kind="Cloudflare Public DNS" ;;
                8.8.8.8|8.8.4.4)              kind="Google Public DNS" ;;
                9.9.9.9|149.112.112.112)      kind="Quad9 Threat-Blocking DNS" ;;
                94.140.14.14|94.140.15.15)    kind="AdGuard Public DNS" ;;
                *)                            kind="Public / Upstream DNS" ;;
            esac
            echo -e "    - ${CYAN}${ns}${NC} (${kind})"
        done < <(grep '^nameserver' "$resolv" 2>/dev/null)
        if [[ "$count" -eq 0 ]]; then
            log_crit "No active nameservers defined in /etc/resolv.conf! DNS resolution will fail!"
        else
            log_pass "Extracted ${count} active DNS nameserver(s)."
        fi
    fi

    subsection "Encrypted DNS (DoH / DoT), DNSSEC & Resolver Security Audit"
    if have resolvectl; then
        local status proto dot dnssec
        status=$(resolvectl status 2>/dev/null)
        if [[ -n "$status" ]]; then
            proto=$(awk '/^Global/ {g = 1; next} /^Link / {g = 0} g && /Protocols:/ {print; exit}' <<< "$status")
            [[ -z "$proto" ]] && proto=$(grep -m1 'Protocols:' <<< "$status")
            dot=$(grep -oE '[+-]DNSOverTLS' <<< "$proto" | head -n 1)
            dnssec=$(grep -oE 'DNSSEC=[^ ]+' <<< "$proto" | head -n 1)
            echo -e "  systemd-resolved DoT Status : ${CYAN}${dot:-Not reported}${NC}"
            echo -e "  systemd-resolved DNSSEC     : ${CYAN}${dnssec:-Not reported}${NC}"
            if [[ "$dot" == "+DNSOverTLS" ]]; then
                log_pass "DNS-over-TLS (DoT) is active in systemd-resolved."
            else
                log_warn "DNS-over-TLS (DoT) is NOT enabled in systemd-resolved (DNS queries are transmitted in plain text)."
            fi
            if [[ "$dnssec" =~ yes|allow-downgrade ]]; then
                log_pass "DNSSEC validation is active in systemd-resolved."
            else
                echo -e "  ${YELLOW}Tip: Consider enabling DNSSEC in /etc/systemd/resolved.conf (DNSSEC=allow-downgrade).${NC}"
            fi
        fi
    fi

    # dnsmasq (e.g. libvirt's) is a plain-text forwarder; unbound counts only with TLS upstreams
    local proxies=(cloudflared dnscrypt-proxy stubby adguardhome) proxy running=""
    grep -rqsE '^[[:space:]]*forward-tls-upstream:[[:space:]]*yes' /etc/unbound/ && proxies+=(unbound)
    for proxy in "${proxies[@]}"; do
        pgrep -x "$proxy" &>/dev/null && running+="${proxy} "
    done
    [[ -n "$running" ]] && log_pass "Active Encrypted DNS / DoH Proxy Daemon(s) detected: ${running}"

    subsection "DNS Resolution Hijacking & /etc/hosts Integrity Audit"
    if [[ -f /etc/hosts ]]; then
        local custom
        custom=$(grep -vE '^[[:space:]]*#|localhost|127\.0\.0\.1|127\.0\.1\.1|::1|fe00::0|ff02::' /etc/hosts | grep -v '^[[:space:]]*$')
        if [[ -n "$custom" ]]; then
            echo -e "${CYAN}Custom /etc/hosts entries:${NC}"
            sed 's/^/  - /' <<< "$custom"
            log_warn "Custom static /etc/hosts overrides detected. Verify that no security or update domains are hijacked."
        else
            log_pass "No unusual custom entries in /etc/hosts."
        fi
    fi

    echo -e "  Testing functional DNS resolution (google.com)..."
    local test_ip
    test_ip=$(getent ahosts google.com 2>/dev/null | awk '{print $1; exit}')
    if [[ -n "$test_ip" ]]; then
        log_pass "System DNS resolution functional (google.com -> ${test_ip})."
    else
        log_warn "System DNS resolution test failed or timed out for google.com!"
    fi
}

# --- Hardware, Wi-Fi & LAN ------------------------------------------------------
audit_devices() {
    subsection "Connected Hardware Devices & Removable Storage Media Audit"

    step "1. Connected USB Devices (lsusb):"
    if have lsusb; then
        local usb
        usb=$(lsusb 2>/dev/null)
        if [[ -n "$usb" ]]; then
            sed 's/^/  - /' <<< "$usb"
            log_pass "Discovered $(wc -l <<< "$usb") connected USB device(s)."
            local suspicious
            suspicious=$(grep -Ei "rubber|ducky|badusb|keysmith|keystroke|wireless[ _]?sniffer|packet[ _]?sniffer|wifi[ _]?pineapple|lan[ _]?turtle|bash[ _]?bunny|pwnagotchi" <<< "$usb")
            [[ -n "$suspicious" ]] && log_crit "POTENTIAL SUSPICIOUS USB DEVICE DETECTED:\n$suspicious"
        else
            echo "No USB devices detected."
        fi
    elif [[ -d /sys/bus/usb/devices ]]; then
        echo -e "  Discovered ${CYAN}$(find /sys/bus/usb/devices -maxdepth 1 -type l | wc -l)${NC} USB device nodes in /sys/bus/usb/devices."
    fi

    step "2. Block Storage Devices & Removable Media (lsblk):"
    if have lsblk; then
        lsblk -o NAME,SIZE,TYPE,TRAN,RM,MOUNTPOINT,RO 2>/dev/null | sed 's/^/  /'
        local dev mnt rm tran removable=""
        while read -r dev; do
            mnt=$(findmnt -rn -o TARGET "/dev/$dev" 2>/dev/null | head -n 1)
            [[ -n "$mnt" ]] || continue
            rm=$(lsblk -ndo RM "/dev/$dev" 2>/dev/null | tr -d ' ')
            tran=$(lsblk -ndo TRAN "/dev/$dev" 2>/dev/null | tr -d ' ')
            if [[ "$rm" == "1" || "$tran" =~ ^(usb|mmc)$ || "$dev" == mmcblk* ]]; then
                removable+="${dev} ${mnt}"$'\n'
            fi
        done < <(lsblk -rno NAME 2>/dev/null)
        removable=${removable%$'\n'}

        if [[ -z "$removable" ]]; then
            log_pass "No mounted removable storage drives (USB/SD cards) detected."
        else
            log_info "Mounted removable storage media (USB / SD card):\n$removable"
            local opts
            while read -r dev mnt; do
                opts=$(findmnt -n -o OPTIONS "$mnt" 2>/dev/null)
                if [[ "$opts" != *nosuid* ]]; then
                    log_warn "Removable media mounted at '${mnt}' lacks the 'nosuid' flag (options: ${opts:-default})."
                elif [[ "$opts" != *noexec* ]]; then
                    log_info "Removable media at '${mnt}' is mounted nosuid but without 'noexec' (normal for data cards; add noexec if you never run programs from it)."
                else
                    log_pass "Removable media mounted at '${mnt}' has secure mount options (${opts})."
                fi
            done <<< "$removable"
        fi
    fi

    step "3. PCI Hardware Controllers (lspci):"
    have lspci && lspci 2>/dev/null | grep -Ei "VGA|Network|Ethernet|Wireless|Thunderbolt|RAID|SATA|NVMe" | head -n 10 | sed 's/^/  - /'

    step "4. Bluetooth Adapter & Pairing Status:"
    if have bluetoothctl; then
        local bt bt_power bt_disc
        bt=$(bluetoothctl show 2>/dev/null)
        if [[ -n "$bt" ]]; then
            bt_power=$(awk '/Powered:/ {print $2; exit}' <<< "$bt")
            bt_disc=$(awk '/Discoverable:/ {print $2; exit}' <<< "$bt")
            echo -e "  Bluetooth Powered     : ${CYAN}${bt_power:-unknown}${NC}"
            echo -e "  Bluetooth Discoverable: ${CYAN}${bt_disc:-unknown}${NC}"
            if [[ "$bt_disc" == "yes" ]]; then
                log_warn "Bluetooth adapter is DISCOVERABLE to nearby un-paired devices!"
            else
                log_pass "Bluetooth adapter is non-discoverable."
            fi
        else
            echo "Bluetooth controller inactive or not present."
        fi
    elif have hciconfig; then
        hciconfig 2>/dev/null | grep -E "hci[0-9]|UP|RUNNING|ISCAN|PSCAN" | sed 's/^/  - /'
    else
        echo "Bluetooth stack/tools not present."
    fi
}

audit_wifi_and_lan() {
    subsection "Primary Network Interface & Subnet Info"
    local route gw iface cidr="" network=""
    route=$(ip route show default 2>/dev/null | head -n 1)
    if [[ -n "$route" ]]; then
        gw=$(awk '{print $3}' <<< "$route")
        iface=$(awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' <<< "$route")
        cidr=$(ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4; exit}')
        network=$(ip -4 route show dev "$iface" scope link proto kernel 2>/dev/null | awk '{print $1; exit}')
        echo -e "Primary Interface: ${CYAN}${iface}${NC} | Local IP: ${CYAN}${cidr}${NC} | Gateway: ${CYAN}${gw}${NC}"
    else
        echo "No active default network gateway found."
    fi

    subsection "Wi-Fi Networks & Connected Access Point Security"
    if have nmcli; then
        # Terse output for logic: "IN-USE:SECURITY:SSID" (SSID last: it may contain ':'); '--' = open network
        local wifi_terse current_sec open_count
        wifi_terse=$(nmcli -t -f IN-USE,SECURITY,SSID dev wifi 2>/dev/null)
        current_sec=$(awk -F: '$1 == "*" {print $2; exit}' <<< "$wifi_terse")
        if [[ -n "$current_sec" ]]; then
            echo -e "${CYAN}Currently Connected Wi-Fi Network:${NC}"
            nmcli -f IN-USE,SSID,BSSID,RATE,SIGNAL,SECURITY dev wifi 2>/dev/null | grep '^\*'
            echo -n "Connected Security Protocol Assessment: "
            case "$current_sec" in
                ""|--)  log_crit "Connected to an UNENCRYPTED (OPEN) Wi-Fi network! Traffic can be intercepted." ;;
                *WEP*)  log_warn "Connected to obsolete/vulnerable ${current_sec} network." ;;
                *WPA3*) log_pass "WPA3 Security (Strongest modern encryption standard)." ;;
                *WPA2*) log_pass "WPA2 Security (Secure standard)." ;;
                *WPA1*) log_warn "Connected to obsolete/vulnerable ${current_sec} network." ;;
                *)      echo -e "${CYAN}${current_sec}${NC}" ;;
            esac
        else
            echo "Not connected to any Wi-Fi access point."
        fi

        step "Nearby Wi-Fi Access Points in Range:"
        local list
        list=$(nmcli -f SSID,BSSID,SIGNAL,SECURITY dev wifi 2>/dev/null | head -n 12)
        if [[ -n "$list" ]]; then
            echo "$list"
            open_count=$(awk -F: '$2 == "--" || $2 == ""' <<< "$wifi_terse" | grep -c .)
            [[ "$open_count" -gt 0 ]] && log_warn "${open_count} open/unencrypted Wi-Fi network(s) detected nearby!"
        else
            echo "No nearby Wi-Fi networks found or Wi-Fi adapter disabled."
        fi
    else
        echo -e "${YELLOW}nmcli not available for Wi-Fi scanning.${NC}"
    fi

    subsection "Local Subnet Active Hosts Discovery"
    [[ -n "$cidr" ]] || return 0
    # Scan the real local network, but never more than a /24 around our address
    local prefix=${cidr#*/} target="${network:-$cidr}"
    [[ "$prefix" =~ ^[0-9]+$ && "$prefix" -lt 24 ]] && target="${cidr%/*}/24"
    echo -e "Scanning local subnet (${CYAN}${target}${NC})..."
    if have nmap; then
        local hosts
        hosts=$(nmap -sn --host-timeout 3s "$target" 2>/dev/null | grep -E "Nmap scan report|Host is up")
        if [[ -n "$hosts" ]]; then
            echo "$hosts"
            log_pass "Total active hosts discovered on local subnet: $(grep -c "Nmap scan report" <<< "$hosts")"
        fi
    else
        echo -e "${CYAN}Active neighbors (ARP / IP Cache):${NC}"
        ip neighbor show 2>/dev/null | grep -v 'FAILED' | sed 's/^/  - /'
    fi
}

section_hardware_and_lan() {
    audit_devices
    audit_wifi_and_lan
}

# --- Logging & auditing services ------------------------------------------------
section_logging() {
    subsection "System Logging Infrastructure (rsyslog / journald)"
    local logs_working=false
    if unit_active rsyslog; then
        logs_working=true
        log_pass "rsyslog service is active (system logging daemon running)."
    elif unit_exists rsyslog.service; then
        log_warn "rsyslog is installed but NOT running. System events may not be persistently logged."
    fi
    if unit_active systemd-journald; then
        logs_working=true
        log_pass "systemd-journald is active."
    elif [[ -d /run/systemd/journal ]]; then
        log_warn "systemd-journald does not report as active."
    fi

    # Sanity check: are logs actually being written?
    local auth_log=""
    [[ -f /var/log/auth.log ]] && auth_log=/var/log/auth.log
    [[ -f /var/log/secure ]] && auth_log=/var/log/secure
    if [[ -n "$auth_log" ]]; then
        local age_h
        age_h=$(( ($(date +%s) - $(stat -c %Y "$auth_log" 2>/dev/null || echo 0)) / 3600 ))
        if [[ "$age_h" -le 24 ]]; then
            logs_working=true
            log_pass "Auth log '${auth_log}' was updated within the last ${age_h}h (logging is functioning)."
        else
            log_warn "Auth log '${auth_log}' has not been written for ${age_h}h! Logging may be broken."
        fi
    elif have journalctl; then
        if [[ -n "$(journalctl --since "24 hours ago" -n 1 --no-pager 2>/dev/null)" ]]; then
            logs_working=true
            log_pass "journald contains recent entries (last 24h) - event logging is functioning."
        else
            log_warn "journald has NO entries for the last 24 hours! System activity is not being recorded."
        fi
    fi
    if [[ "$logs_working" == false ]]; then
        log_crit "NO ACTIVE LOGGING: neither rsyslog nor a functioning journald/auth log was verified. Security events are NOT being recorded!"
    fi

    subsection "Kernel Audit Framework (auditd)"
    if unit_active auditd; then
        log_pass "auditd service is active (kernel syscall & access auditing enabled)."
        echo -e "  audit.log entries present      : ${CYAN}$(wc -l 2>/dev/null < /var/log/audit/audit.log || echo 0)${NC}"
    elif unit_exists auditd.service; then
        log_warn "auditd is installed but NOT running. Security-relevant events (file access, syscall anomalies) are not audited."
        [[ "$AUTO_RESTART_SERVICES" == true ]] && restart_service "auditd" "enabling kernel security auditing"
    else
        log_warn "auditd is NOT installed. Recommended: 'apt install auditd' / 'dnf install audit' for system activity auditing."
    fi
}

# --- Disk encryption & MAC ------------------------------------------------------
section_encryption_and_mac() {
    subsection "Full Disk Encryption (LUKS) Status"
    local luks_devices=0 root_encrypted=false dev
    if have lsblk; then
        echo "Block device encryption map:"
        lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null | sed 's/^/  /'
        # LUKS is identified via the device stack; /dev/mapper alone could be plain LVM
        root_on_luks && root_encrypted=true
        luks_devices=$(lsblk -rno FSTYPE 2>/dev/null | grep -cx 'crypto_LUKS')
    fi
    if have cryptsetup && [[ "$luks_devices" -eq 0 ]]; then
        while read -r dev; do
            cryptsetup isLuks "$dev" 2>/dev/null && luks_devices=$((luks_devices + 1))
        done < <(lsblk -rno PATH,TYPE 2>/dev/null | awk '$2 == "part" || $2 == "disk" {print $1}' | head -n 20)
    fi
    echo -e "  LUKS-encrypted block devices found : ${CYAN}${luks_devices}${NC}"

    [[ "$root_encrypted" == true ]] && log_pass "Root filesystem resides on a LUKS-encrypted device."

    if grep -qE '^[^#[:space:]]' /etc/crypttab 2>/dev/null; then
        log_pass "crypttab contains active encrypted volume mappings:"
        grep -vE '^[[:space:]]*(#|$)' /etc/crypttab | sed 's/^/    /'
        if awk '!/^[[:space:]]*#/ && $3 ~ /^\// {found = 1} END {exit !found}' /etc/crypttab; then
            log_warn "crypttab uses key files on disk for at least one volume (not passphrase-prompted)."
        fi
    fi

    if [[ "$root_encrypted" == false && "$luks_devices" -eq 0 ]]; then
        log_crit "Root filesystem is on an UNENCRYPTED partition and no LUKS volumes exist! Physical access / disk theft exposes all stored data. Recommended: LUKS full disk encryption."
    elif [[ "$luks_devices" -gt 0 ]]; then
        log_pass "Disk encryption (LUKS) is in use on this system (${luks_devices} encrypted device(s))."
    else
        log_warn "No LUKS-encrypted devices detected (system may be virtual, or disks are unencrypted)."
    fi

    subsection "Mandatory Access Control (SELinux / AppArmor)"
    local mac_active=false
    if have getenforce; then
        local se_mode
        se_mode=$(getenforce 2>/dev/null)
        echo -e "  SELinux status                  : ${CYAN}${se_mode}${NC}"
        case "$se_mode" in
            Enforcing)  log_pass "SELinux is ENFORCING (mandatory access control active)."; mac_active=true ;;
            Permissive) log_warn "SELinux is PERMISSIVE: policy violations are logged but NOT blocked." ;;
            Disabled)   log_warn "SELinux is DISABLED." ;;
        esac
    fi

    local profiles
    profiles=$(wc -l 2>/dev/null < /sys/kernel/security/apparmor/profiles || echo 0)
    if have aa-enabled; then
        aa-enabled &>/dev/null
        case $? in
            0) log_pass "AppArmor is enabled with ${profiles} loaded profile(s)."; mac_active=true ;;
            2) log_warn "AppArmor is enabled but no profiles are loaded." ;;
            *) log_warn "AppArmor is installed but DISABLED." ;;
        esac
    elif [[ -d /sys/kernel/security/apparmor ]]; then
        mac_active=true
        log_pass "AppArmor kernel module active with ${profiles} loaded profile(s)."
    fi

    if [[ "$mac_active" == false ]]; then
        log_crit "NO MANDATORY ACCESS CONTROL ACTIVE: neither SELinux (enforcing) nor AppArmor is protecting this system! Service compromise leads directly to full filesystem access."
    fi
}

# --- Behavioral rootkit indicators ----------------------------------------------
# is_own_descendant PID: PID belongs to this script's process tree
is_own_descendant() {
    local p="$1" pp
    for _ in {1..40}; do
        [[ "$p" == "$$" ]] && return 0
        pp=$(awk '/^PPid:/ {print $2}' "/proc/$p/status" 2>/dev/null)
        [[ -z "$pp" || "$pp" -le 1 ]] && return 1
        p="$pp"
    done
    return 1
}

# PIDs present in /proc but missing from ps. Race-safe: a PID must still exist and still be
# missing from a FRESH ps snapshot a second later, and must not be one of our own short-lived
# helpers (those caused false "hidden process" alarms before).
detect_hidden_pids() {
    local proc_pids ps_pids candidates pid
    proc_pids=$(find /proc -maxdepth 1 -type d -name '[0-9]*' -printf '%f\n' 2>/dev/null | sort)
    ps_pids=$(ps -e -o pid= 2>/dev/null | tr -d ' ' | sort)
    candidates=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids"))
    [[ -n "$candidates" ]] || return 0
    sleep 1
    ps_pids=$(ps -e -o pid= 2>/dev/null | tr -d ' ')
    for pid in $candidates; do
        [[ -d "/proc/$pid" ]] || continue              # short-lived process, already gone
        grep -qx "$pid" <<< "$ps_pids" && continue      # visible to ps now
        is_own_descendant "$pid" && continue            # helper spawned by this script
        echo "PID ${pid} (comm: $(cat "/proc/$pid/comm" 2>/dev/null), user: $(stat -c %U "/proc/$pid" 2>/dev/null))"
    done
}

section_rootkit_indicators() {
    local indicators=0

    step "1. Hidden Process Detection (/proc enumeration vs ps, unhide):"
    local hidden
    hidden=$(detect_hidden_pids)
    if [[ -n "$hidden" ]]; then
        log_crit "HIDDEN PROCESSES DETECTED (present in /proc, absent from 'ps', still alive after re-check):\n$hidden"
        indicators=$((indicators + 1))
    else
        log_pass "No hidden processes: every /proc PID is visible to ps (re-checked after 1s, own helpers excluded)."
    fi
    if have unhide; then
        echo -e "${CYAN}Running deep hidden process detection using 'unhide'...${NC}"
        local unhide_out
        unhide_out=$(unhide -m proc sys 2>/dev/null | grep -i "Found HIDDEN")
        if [[ -n "$unhide_out" ]]; then
            log_crit "Unhide tool detected hidden processes:\n$unhide_out"
            indicators=$((indicators + 1))
        else
            log_pass "unhide found no hidden processes."
        fi
    fi

    step "2. Shared Library Preload Hooks (/etc/ld.so.preload):"
    local preload
    preload=$(grep -vE '^[[:space:]]*(#|$)' /etc/ld.so.preload 2>/dev/null)
    if [[ -n "$preload" ]]; then
        log_crit "LIBRARY PRELOAD HOOK ACTIVE in /etc/ld.so.preload (common userland rootkit technique):\n$preload"
        indicators=$((indicators + 1))
    else
        log_pass "No system-wide library preload hooks (/etc/ld.so.preload empty or absent)."
    fi

    step "3. Running-But-Deleted Binaries (/proc/*/exe with '(deleted)'):"
    local exe target pid deleted=""
    for exe in /proc/[0-9]*/exe; do
        target=$(readlink "$exe" 2>/dev/null)
        [[ "$target" == *" (deleted)" ]] || continue
        pid=${exe#/proc/}; pid=${pid%/exe}
        deleted+="PID ${pid} (User: $(ps -o user= -p "$pid" 2>/dev/null)) -> ${target} [Cmd: $(tr '\0' ' ' 2>/dev/null < "/proc/$pid/cmdline")]\n"
    done
    if [[ -z "$deleted" ]]; then
        log_pass "No processes running from deleted binaries."
    elif [[ -n "$(echo -e "$deleted" | sed '/^$/d' | grep -vE -- '-> /(usr|opt|lib|lib64|bin|sbin)/')" ]]; then
        log_crit "Processes executing deleted binary files outside package-managed paths (typical malware pattern)!\n$deleted"
        indicators=$((indicators + 1))
    else
        # Binaries under package-managed paths replaced by an update: stale, not malicious
        log_warn "Processes still run binaries replaced by a package update (stale until restarted; see needrestart / reboot):\n$deleted"
    fi

    step "4. Promiscuous Mode Network Interfaces (packet sniffing):"
    local promisc
    promisc=$(ip -o link show 2>/dev/null | grep -i 'promisc' | awk -F': ' '{print $2}')
    if [[ -n "$promisc" ]]; then
        log_warn "Network interface(s) in PROMISCUOUS MODE (traffic capture active): ${promisc}"
        indicators=$((indicators + 1))
    else
        log_pass "No network interfaces in promiscuous mode."
    fi

    step "5. Core Binary Path Hijack Check (world-writable system tools):"
    local hijack
    hijack=$(find /sbin /usr/sbin /bin /usr/bin -maxdepth 1 -type f \( -name ls -o -name ps -o -name netstat -o -name top -o -name id -o -name who \) -perm -0002 2>/dev/null)
    if [[ -n "$hijack" ]]; then
        log_crit "CORE SYSTEM BINARIES ARE WORLD-WRITABLE (trojanized binary risk):\n$hijack"
        indicators=$((indicators + 1))
    else
        log_pass "Core system binaries are not world-writable."
    fi

    step "6. Kernel Module Anomalies (lsmod vs /sys/module):"
    if have lsmod; then
        local lsmod_mods sys_mods hidden_mods d n
        lsmod_mods=$(lsmod 2>/dev/null | awk 'NR > 1 {print $1}' | tr '-' '_' | sort)
        # Only LOADABLE modules expose /sys/module/<name>/initstate; built-in components
        # (acpi, block, apparmor, 8250 ...) have no initstate file and are not modules
        sys_mods=$(for d in /sys/module/*/initstate; do [[ -e "$d" ]] || continue; n=${d#/sys/module/}; echo "${n%/initstate}"; done | tr '-' '_' | sort)
        hidden_mods=$(comm -23 <(echo "$sys_mods") <(echo "$lsmod_mods") | head -n 20)
        if [[ -n "$hidden_mods" ]]; then
            log_crit "Loadable kernel modules present in /sys/module but missing from lsmod (module-hiding rootkit indicator):\n$hidden_mods"
            indicators=$((indicators + 1))
        else
            log_pass "No hidden kernel modules detected (sysfs and lsmod agree on all loadable modules)."
        fi
    fi

    if [[ "$indicators" -eq 0 ]]; then
        echo -e "\n${GREEN}Behavioral rootkit scan: no anomalous process, preload, module or interface indicators found.${NC}"
    else
        echo -e "\n${RED}Behavioral rootkit scan: ${indicators} indicator(s) found (each counted above). Investigate them and compare with the chkrootkit result.${NC}"
    fi
}

# ==============================================================================
# Wrap-up
# ==============================================================================
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

    # Leftover temp files from an interrupted dictionary download ($WORK_DIR is removed on exit)
    find "$REPORT_DIR" "${DICT_CACHE_DIR:-$REPORT_DIR}" -maxdepth 1 -name "*.tmp" -type f -delete 2>/dev/null

    echo -e "  ${CYAN}Left on disk:${NC}"
    echo -e "    - Audit report        : ${CYAN}${REPORT_FILE}${NC}"
    [[ -s "$DICT_FILE" ]] && echo -e "    - Password dictionary : ${CYAN}${DICT_FILE}${NC} (cached for future runs)"
    [[ "$CLEAN_HISTORY" == true ]] && echo -e "    - History backups     : *.audit-backup (contain the removed lines - delete when no longer needed)"
    [[ "$AUTO_FIX" == true ]] && echo -e "    - Remediations        : permission/config fixes applied by --fix (see [OK] lines above)"
    echo ""
}

print_scorecard() {
    local end_sec duration mins secs score=100
    end_sec=$(date +%s)
    duration=$(( end_sec - AUDIT_START_TIME_SEC ))
    mins=$(( duration / 60 ))
    secs=$(( duration % 60 ))

    # Criticals weigh heavily; warnings are capped so many small suggestions cannot zero the score
    if [[ "$TOTAL_CHECKS" -gt 0 ]]; then
        local warn_penalty=$(( WARNING_COUNT > 25 ? 25 : WARNING_COUNT ))
        score=$(( 100 - CRITICAL_COUNT * 12 - warn_penalty ))
        [[ "$score" -lt 0 ]] && score=0
    fi

    printf "  %-30s : %s\n" "Audit Started At" "$AUDIT_START_TIME_STR"
    printf "  %-30s : %s\n" "Audit Completed At" "$(date "+%Y-%m-%d %H:%M:%S %Z")"
    printf "  %-30s : %s\n" "Total Execution Duration" "$( [[ $mins -gt 0 ]] && echo "${mins}m ${secs}s" || echo "${secs}s")"
    echo -e "-----------------------------------------------------"
    printf "  %-30s : %d\n" "Total Security Checks" "$TOTAL_CHECKS"
    printf "  %-30s : ${GREEN}%d${NC}\n" "Checks Passed" "$PASSED_COUNT"
    printf "  %-30s : ${YELLOW}%d${NC}\n" "Warnings / Suggestions" "$WARNING_COUNT"
    printf "  %-30s : ${RED}%d${NC}\n" "Critical Vulnerabilities" "$CRITICAL_COUNT"
    echo -e "-----------------------------------------------------"

    local width=20 filled bar color
    filled=$(( score * width / 100 ))
    bar=$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' $(( width - filled )) '' | tr ' ' '-')
    if [[ "$score" -ge 80 ]]; then color=$GREEN; elif [[ "$score" -ge 50 ]]; then color=$YELLOW; else color=$RED; fi
    echo -e "  Overall Security Score        : ${color}${score}% [${bar}]${NC}"

    echo -e "${CYAN}=====================================================${NC}"
    local mode="report-only (no changes made)"
    if [[ "$AUTO_FIX" == true || "$INSTALL_MISSING_PKGS" == true || "$UPDATE_SECURITY_DATABASES" == true || "$CLEAN_CACHE" == true \
          || "$CLEAN_HISTORY" == true || "$AUTO_RESTART_SERVICES" == true || "$REFRESH_EXTERNAL_PASSWORDS" == true ]]; then
        mode="changes enabled via flags"
    fi
    echo -e "${GREEN}[OK] System audit finished - mode: ${mode}.${NC}"
    echo -e "  Detailed Markdown Report Log: ${CYAN}${REPORT_FILE}${NC}"
    echo -e "${CYAN}=====================================================${NC}"
}

run_sections() {
    local entry id title fn selected=()
    for entry in "${SECTIONS[@]}"; do
        section_selected "${entry%%|*}" && selected+=("$entry")
    done
    SECTION_TOTAL=${#selected[@]}
    for entry in "${selected[@]}"; do
        IFS='|' read -r id title fn <<< "$entry"
        section "${title}..."
        "$fn"
    done
}

main() {
    parse_args "$@"
    require_root

    AUDIT_START_TIME_SEC=$(date +%s)
    AUDIT_START_TIME_STR=$(date "+%Y-%m-%d %H:%M:%S %Z")
    setup_report
    print_banner
    preflight_tools

    [[ "$AUTO_FIX" == true ]] && apply_fixes
    if [[ "$UPDATE_SECURITY_DATABASES" == true ]]; then
        update_security_databases
    else
        log_info "Security database refresh skipped (report-only). Use --update-db to refresh APT/ClamAV/Trivy databases."
    fi

    run_sections
    report_footprint
    print_scorecard

    [[ "$CRITICAL_COUNT" -gt 0 ]] && exit 1
    exit 0
}

main "$@"
