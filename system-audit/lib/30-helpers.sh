# Generic helpers used by the checks.

# have TOOL: available on this system (pre-flight result if the tool was checked there)
have() {
    if [[ -n "${TOOL_FOUND[$1]+set}" ]]; then
        [[ "${TOOL_FOUND[$1]}" -eq 1 ]]
    else
        command -v "$1" &>/dev/null
    fi
}

# matches REGEX TEXT: extended-regex match on captured text (safe under pipefail)
matches() { grep -qE -- "$1" <<< "$2"; }

# count_lines TEXT: number of non-empty lines
count_lines() { grep -c . <<< "$1"; }

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

# The root filesystem plus the usual separate mounts: with -xdev each is walked exactly once
local_fs_roots() {
    local mp
    echo /
    for mp in /home /var /opt /srv /usr /boot /tmp; do
        mountpoint -q "$mp" 2>/dev/null && echo "$mp"
    done
}

# scan_find ROOT... [GLOBAL-OPTION...] -- TEST...: find on local filesystems that skips
# SCAN_EXCLUDES (pseudo filesystems, container/VM storage) and prints the matches.
#   scan_find /etc /var -maxdepth 4 -- \( -nouser -o -nogroup \)
scan_find() {
    local roots=() opts=() prune=() pattern
    while [[ $# -gt 0 && "$1" != "--" ]]; do
        if [[ "$1" == -* ]]; then opts+=("$1"); else roots+=("$1"); fi
        # option values (e.g. the 4 of -maxdepth 4) follow their option
        if [[ "$1" == -maxdepth || "$1" == -mindepth ]]; then opts+=("$2"); shift; fi
        shift
    done
    shift
    for pattern in "${SCAN_EXCLUDES[@]}"; do
        prune+=(-path "$pattern" -o)
    done
    unset 'prune[${#prune[@]}-1]'
    find "${roots[@]}" "${opts[@]}" -xdev \( "${prune[@]}" \) -prune -o \( "$@" \) -print 2>/dev/null
}

# slow_scan NAME: false (with a note) in --quick mode, which skips the slow external scanners
slow_scan() {
    [[ "$QUICK_MODE" == true ]] || return 0
    echo -e "${DIM}  ${1}: skipped (--quick).${NC}"
    return 1
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

restart_service() {   # restart_service UNIT [REASON]
    local service="$1" reason="${2:-auto-remediation}"
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
