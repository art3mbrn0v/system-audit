# Behavioral rootkit indicators (no signature database).

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
    subsection "Hidden Processes (/proc vs ps, unhide)"
    local hidden unhide_out
    hidden=$(detect_hidden_pids)
    if [[ -n "$hidden" ]]; then
        log_crit "Hidden processes (in /proc, invisible to ps, still alive after re-check):" "$hidden"
    else
        log_pass "Every /proc PID is visible to ps (no hidden processes)."
    fi
    if have unhide && slow_scan "unhide brute-force PID scan"; then
        echo "  Running unhide (brute-force PID scan, takes a few minutes)..."
        unhide_out=$(unhide -m proc sys 2>/dev/null | grep -i "Found HIDDEN")
        if [[ -n "$unhide_out" ]]; then
            log_crit "unhide found hidden processes:" "$unhide_out"
        else
            log_pass "unhide found no hidden processes."
        fi
    fi

    subsection "Preload Hooks, Deleted Binaries, Sniffing, Hidden Modules"
    local preload
    preload=$(grep -vE '^[[:space:]]*(#|$)' /etc/ld.so.preload 2>/dev/null)
    if [[ -n "$preload" ]]; then
        log_crit "Libraries preloaded into every process via /etc/ld.so.preload (classic userland rootkit):" "$preload"
    else
        log_pass "No system-wide library preload hooks (/etc/ld.so.preload)."
    fi

    local exe target pid deleted=() foreign=()
    for exe in /proc/[0-9]*/exe; do
        target=$(readlink "$exe" 2>/dev/null)
        [[ "$target" == *" (deleted)" ]] || continue
        pid=${exe#/proc/}; pid=${pid%/exe}
        deleted+=("PID ${pid} ($(ps -o user= -p "$pid" 2>/dev/null)): ${target}")
        # Binaries under package-managed paths replaced by an update are stale, not malicious
        [[ "$target" =~ ^/(usr|opt|lib|lib64|bin|sbin)/ ]] || foreign+=("PID ${pid}: ${target} [$(tr '\0' ' ' 2>/dev/null < "/proc/$pid/cmdline")]")
    done
    if [[ ${#foreign[@]} -gt 0 ]]; then
        log_crit "Processes running deleted binaries from outside package-managed paths (typical malware pattern):" "${foreign[@]}"
    elif [[ ${#deleted[@]} -gt 0 ]]; then
        log_info "Processes still run binaries replaced by a package update (restart them or reboot):" "${deleted[@]}"
    else
        log_pass "No processes run deleted binaries."
    fi

    local promisc
    promisc=$(ip -o link show 2>/dev/null | grep -i 'promisc' | awk -F': ' '{print $2}')
    if [[ -n "$promisc" ]]; then
        log_warn "Network interfaces in promiscuous mode (traffic capture is running):" "$promisc"
    else
        log_pass "No network interface is in promiscuous mode."
    fi

    local hijack
    hijack=$(find /sbin /usr/sbin /bin /usr/bin -maxdepth 1 -type f \( -name ls -o -name ps -o -name netstat -o -name top -o -name id -o -name who \) -perm -0002 2>/dev/null)
    [[ -n "$hijack" ]] && log_crit "Core system tools are world-writable (can be trojanized):" "$hijack"

    if have lsmod; then
        local lsmod_mods sys_mods hidden_mods d n
        lsmod_mods=$(lsmod 2>/dev/null | awk 'NR > 1 {print $1}' | tr '-' '_' | sort)
        # Only LOADABLE modules expose /sys/module/<name>/initstate; built-in components
        # (acpi, block, apparmor, 8250 ...) have no initstate file and are not modules
        sys_mods=$(for d in /sys/module/*/initstate; do [[ -e "$d" ]] || continue; n=${d#/sys/module/}; echo "${n%/initstate}"; done | tr '-' '_' | sort)
        hidden_mods=$(comm -23 <(echo "$sys_mods") <(echo "$lsmod_mods"))
        if [[ -n "$hidden_mods" ]]; then
            log_crit "Kernel modules loaded but hidden from lsmod (module-hiding rootkit indicator):" "$hidden_mods"
        else
            log_pass "No hidden kernel modules (sysfs and lsmod agree)."
        fi
    fi
}

register_section rootkit "Behavioral Rootkit Indicators (hidden processes, preload hooks, modules)" section_rootkit_indicators
