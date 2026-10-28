# Settings, defaults and tunables of the audit.

# Locale-independent parsing of tool output (ss, last, passwd -S, top, ...)
export LC_ALL=C
umask 077
# With pipefail, `producer | grep -q` reports failure whenever grep exits early and the
# producer dies of SIGPIPE. Never test such a pipeline: capture the text, then use matches().
set -o pipefail

VERSION="4.0"
# Resolve sbin tools even when sudo/su did not set a root PATH (the $PATH audit checks the original)
ORIGINAL_PATH="$PATH"
PATH="/usr/local/sbin:/usr/sbin:/sbin:${PATH}"

# --- Run modes: safe by default, the audit only READS. Every change is opt-in via a flag ---
AUTO_FIX=false
CLEAN_CACHE=false
CLEAN_HISTORY=false
AUTO_RESTART_SERVICES=false
INSTALL_MISSING_PKGS=false
UPDATE_SECURITY_DATABASES=false
FETCH_EXTERNAL_PASSWORDS=true
REFRESH_EXTERNAL_PASSWORDS=false
QUICK_MODE=false          # --quick: skip slow external scanners
REPORT_DIR="${AUDIT_ROOT}/reports"
ONLY_SECTIONS=""
SKIP_SECTIONS=""

# Detail lines shown per finding (terminal and report); the rest is summarized as "... N more"
MAX_DETAILS=20

# Skipped by filesystem-wide scans (world-writable, orphaned, SUID ...): pseudo filesystems and
# container / VM / sandbox storage. Their content belongs to images, sits under root-only
# directories and is full of world-writable paths that are no risk to the host.
# Patterns are find(1) -path globs; --exclude adds more.
SCAN_EXCLUDES=(
    /proc /sys /dev /run
    /var/lib/docker /var/lib/containerd /var/lib/containers
    /var/lib/lxc /var/lib/lxd /var/lib/libvirt/images
    /var/lib/flatpak /var/lib/snapd /snap
    "/home/*/.local/share/containers" "/home/*/.local/share/flatpak"
)

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

# Colors (stripped from the log file)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

# Runtime state
declare -A TOOL_FOUND=()
declare -A AUDIT_INSTALLED_PKGS=()   # packages installed BY THIS RUN (--install)
PKG_MGR=""          # apt | dnf | empty
WORK_DIR=""         # private scratch dir, removed on exit
REPORT_FILE=""      # Markdown summary
LOG_FILE=""         # full plain-text output
TEE_PID=""
AUDIT_INTERRUPTED=false
