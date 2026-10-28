# Docker / Podman containers.

section_containers() {
    if [[ -S /var/run/docker.sock ]]; then
        echo -e "  Docker socket: ${CYAN}$(stat -c '%A %U:%G' /var/run/docker.sock 2>/dev/null)${NC}"
        mode_has "$(file_mode /var/run/docker.sock)" 002 && log_crit "Docker socket is world-writable: every local user is effectively root."
    else
        echo "  Docker socket (/var/run/docker.sock) not active."
    fi

    if have docker && docker ps &>/dev/null; then
        subsection "Running Docker Containers"
        local running privileged host_net sock_mounts
        running=$(docker ps --format '{{.Names}} ({{.Image}})' 2>/dev/null)
        echo "${running:-  No running containers.}" | sed 's/^/  /'
        [[ -n "$running" ]] || return 0
        local inspect
        inspect=$(docker ps --quiet | xargs -r docker inspect --format \
            '{{.Name}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null)
        privileged=$(awk -F'|' '$2 == "true" {print substr($1, 2)}' <<< "$inspect")
        host_net=$(awk -F'|' '$3 == "host" {print substr($1, 2)}' <<< "$inspect")
        sock_mounts=$(awk -F'|' '$4 ~ /docker\.sock/ {print substr($1, 2)}' <<< "$inspect")
        [[ -n "$privileged" ]] && log_warn "Privileged containers (full access to host devices and kernel):" "$privileged"
        [[ -n "$sock_mounts" ]] && log_warn "Containers with the Docker socket mounted (can control the host):" "$sock_mounts"
        [[ -n "$host_net" ]] && log_info "Containers using the host network namespace:" "$host_net"
        [[ -z "$privileged$sock_mounts" ]] && log_pass "No privileged containers and no Docker socket mounts."
    elif have podman && podman ps &>/dev/null; then
        subsection "Running Podman Containers"
        podman ps --format '{{.Names}} ({{.Image}})' 2>/dev/null | sed 's/^/  /'
    fi
}

register_section containers "Docker & Container Security" section_containers
