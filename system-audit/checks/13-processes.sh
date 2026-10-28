# Running processes: malware indicators and resource usage.

section_processes() {
    # One snapshot for all pattern checks (without the audit's own processes)
    local snapshot
    snapshot=$(ps -eo user,pid,args 2>/dev/null | grep -v "system-audit")

    subsection "Suspicious Processes"
    local exe target pid temp_procs=()
    for exe in /proc/[0-9]*/exe; do
        target=$(readlink "$exe" 2>/dev/null)
        [[ "$target" =~ ^(/tmp/|/var/tmp/|/dev/shm/) ]] || continue
        pid=${exe#/proc/}; pid=${pid%/exe}
        temp_procs+=("PID ${pid} ($(ps -o user= -p "$pid" 2>/dev/null)): ${target} [$(tr '\0' ' ' 2>/dev/null < "/proc/$pid/cmdline")]")
    done
    if [[ ${#temp_procs[@]} -gt 0 ]]; then
        log_warn "Processes running binaries from temporary directories:" "${temp_procs[@]}"
    else
        log_pass "No processes run binaries from /tmp, /var/tmp or /dev/shm."
    fi

    local hits
    hits=$(grep -Ei "xmrig|minerd|cgminer|cpuminer|kworkerds|stratum|masscan|zmap|kinsing|sysupdate" <<< "$snapshot")
    if [[ -n "$hits" ]]; then
        log_crit "Known crypto-miner or mass-scanner processes:" "$hits"
    else
        log_pass "No known miner or mass-scanner processes."
    fi

    hits=$(grep -Ei "nc -e|nc\.openbsd -e|bash -i|sh -i|python.*socket|perl.*socket|php -r.*socket" <<< "$snapshot")
    if [[ -n "$hits" ]]; then
        log_crit "Processes matching reverse-shell patterns:" "$hits"
    else
        log_pass "No reverse-shell command patterns."
    fi

    local zombies
    zombies=$(ps -eo pid=,ppid=,user=,stat=,comm= 2>/dev/null \
              | awk '$4 ~ /^Z/ {print "PID " $1 " (" $5 ", " $3 "), parent PID " $2}')
    if [[ -n "$zombies" ]]; then
        # A zombie is already dead; only its parent can reap it (this script never kills processes)
        log_info "Zombie processes (harmless unless they pile up; restart the parent if they persist):" "$zombies"
    fi

    # Orphans: re-parented to PID 1, owned by a normal user, running a binary OUTSIDE
    # package-managed locations (desktop daemons under /usr or /opt are normal)
    local opid ouser oexe orphans=()
    while read -r opid ouser; do
        oexe=$(readlink "/proc/$opid/exe" 2>/dev/null)
        case "$oexe" in
            ""|/usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/opt/*|/snap/*|/nix/store/*) continue ;;
        esac
        orphans+=("PID ${opid} (${ouser}): ${oexe}")
    done < <(ps -eo pid=,ppid=,user= 2>/dev/null | awk '$2 == 1 && $1 != 1 && $3 != "root" {print $1, $3}')
    if [[ ${#orphans[@]} -gt 0 ]]; then
        log_warn "Detached user processes running binaries outside package-managed paths:" "${orphans[@]}"
    else
        log_pass "No detached user processes run binaries from non-system locations."
    fi

    subsection "CPU & Memory Usage"
    local high_cpu
    # ps %cpu is a lifetime average (a just-started 'ps' reports 100%), so sample 1s with top instead
    high_cpu=$(top -b -n 2 -d 1 -w 512 2>/dev/null | awk '/^top -/ {frame++} frame == 2 && $1 ~ /^[0-9]+$/ && $9 + 0 > 70.0 && $12 != "top" {printf "PID %s %s: %s%% CPU, %s%% MEM\n", $1, $12, $9, $10}')
    if [[ -n "$high_cpu" ]]; then
        log_info "Processes using more than 70% CPU right now:" "$high_cpu"
    else
        echo "  No process uses more than 70% CPU."
    fi
    echo -e "  ${CYAN}Top 5 processes by memory:${NC}"
    ps -eo pid,user,%cpu,%mem,comm --sort=-%mem | head -n 6 | sed 's/^/  /'
}

register_section processes "Running Processes: Malware Indicators & Resource Usage" section_processes
