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
#   --quick              skip slow scanners (ClamAV, chkrootkit, debsums, Lynis, Trivy,
#                        unhide, nmap, weak-password dictionary): minutes instead of 10+
#   --report-dir DIR     where to write the report (default: ./reports)
#   --exclude PATH       skip PATH in filesystem-wide scans (repeatable; container
#                        and VM storage such as /var/lib/docker is skipped by default)
#   --only IDS           run only these sections (comma-separated ids, see --list)
#   --skip IDS           run all sections except these
#   --list               list section ids and exit
#   -h, --help           show this help
# Output: <report-dir>/audit-<date>.md (summary & findings) and audit-<date>.log (full output)
# Exit code: 0 = no critical findings, 1 = critical findings, 2 = usage error
# ==============================================================================

AUDIT_ENTRY="$(readlink -f "${BASH_SOURCE[0]}")"
AUDIT_ROOT="$(dirname "$AUDIT_ENTRY")"
AUDIT_LIB="${AUDIT_ROOT}/system-audit/lib"

# Libraries first (config, output, helpers, run logic), then the checks; each
# checks/NN-*.sh registers its section, and the file name prefix sets the run order
for _module in "$AUDIT_LIB"/*.sh "$AUDIT_ROOT"/system-audit/checks/*.sh; do
    # shellcheck source=/dev/null
    source "$_module" || { echo "Error: cannot load ${_module}" >&2; exit 2; }
done
unset _module

main "$@"
