#!/bin/bash
# firewalld check/fix/verify script
# Standard:
# - firewalld must be enabled and active
# - public zone: interface enp2s0 only, no sources, no services, no ports, no rich rules
# - allowed zone: regular IPs + standard TCP/UDP ports
# - allowed_http zone: HTTP IPs + standard TCP/UDP ports + 80/tcp
# - trusted zone: no managed sources
# - LogDenied must be unicast
# - rsyslog writes firewall logs to /var/log/firewall.log
# - logrotate rotates /var/log/firewall.log

set -euo pipefail
IFS=$'\n\t'

CONFIG_FILE="${CONFIG_FILE:-/etc/firewall-standard.conf}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "[ERROR] Config file not found: $CONFIG_FILE"
    echo "[INFO] Copy firewall-standard.example.conf to /etc/firewall-standard.conf and edit it"
    exit 1
fi

# shellcheck source=/etc/firewall-standard.conf
. "$CONFIG_FILE"

PUBLIC_ZONE="public"
ALLOWED_ZONE="allowed"
ALLOWED_HTTP_ZONE="allowed_http"

INTERFACE="${INTERFACE:-${CONFIG_INTERFACE:-}}"

RSYSLOG_CONF="/etc/rsyslog.d/10-firewall.conf"
LOGROTATE_CONF="/etc/logrotate.d/firewall"

NEEDS_FIX=0
FIX_DONE=0
BACKUP_DIR=""

say() {
    echo "$@"
}

contains() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        [ "$item" = "$needle" ] && return 0
    done
    return 1
}

zone_exists() {
    local zone="$1"
    firewall-cmd --permanent --get-zones 2>/dev/null | tr ' ' '\n' | grep -Fxq "$zone"
}

list_sources() {
    local zone="$1"
    firewall-cmd --permanent --zone="$zone" --list-sources 2>/dev/null | tr ' ' '\n' | sed '/^$/d' || true
}

list_ports() {
    local zone="$1"
    firewall-cmd --permanent --zone="$zone" --list-ports 2>/dev/null | tr ' ' '\n' | sed '/^$/d' || true
}

list_services() {
    local zone="$1"
    firewall-cmd --permanent --zone="$zone" --list-services 2>/dev/null | tr ' ' '\n' | sed '/^$/d' || true
}

list_interfaces() {
    local zone="$1"
    firewall-cmd --permanent --zone="$zone" --list-interfaces 2>/dev/null | tr ' ' '\n' | sed '/^$/d' || true
}

list_rich_rules() {
    local zone="$1"
    firewall-cmd --permanent --zone="$zone" --list-rich-rules 2>/dev/null || true
}

has_source() {
    local zone="$1"
    local source="$2"
    list_sources "$zone" | grep -Fxq "$source"
}

has_port() {
    local zone="$1"
    local port="$2"
    list_ports "$zone" | grep -Fxq "$port"
}

has_interface() {
    local zone="$1"
    local interface="$2"
    list_interfaces "$zone" | grep -Fxq "$interface"
}

is_allowed_port() {
    local port="$1"
    local p

    for p in "${TCP_PORTS[@]}"; do
        [ "$port" = "${p}/tcp" ] && return 0
    done

    for p in "${UDP_PORTS[@]}"; do
        [ "$port" = "${p}/udp" ] && return 0
    done

    return 1
}

is_allowed_http_port() {
    local port="$1"
    local p

    for p in "${TCP_PORTS[@]}"; do
        [ "$port" = "${p}/tcp" ] && return 0
    done

    for p in "${UDP_PORTS[@]}"; do
        [ "$port" = "${p}/udp" ] && return 0
    done

    for p in "${HTTP_EXTRA_TCP_PORTS[@]}"; do
        [ "$port" = "${p}/tcp" ] && return 0
    done

    return 1
}

is_managed_source() {
    local source="$1"
    contains "$source" "${IPS[@]}" && return 0
    contains "$source" "${HTTP_IPS[@]}" && return 0
    return 1
}

mark_fix() {
    say "[CHECK] $1"
    NEEDS_FIX=1
}

check_array_duplicates() {
    local duplicate_found=0
    local ip1
    local ip2

    for ip1 in "${IPS[@]}"; do
        for ip2 in "${HTTP_IPS[@]}"; do
            if [ "$ip1" = "$ip2" ]; then
                say "[ERROR] Duplicate IP in IPS and HTTP_IPS: $ip1"
                duplicate_found=1
            fi
        done
    done

    if [ "$duplicate_found" -eq 1 ]; then
        say "[ERROR] Fix duplicate IPs in the script before running"
        exit 1
    fi
}

basic_checks() {
    if [ "$EUID" -ne 0 ]; then
        say "[ERROR] Run this script as root"
        exit 1
    fi

    if ! command -v firewall-cmd >/dev/null 2>&1; then
        say "[ERROR] firewall-cmd not found. Install firewalld first"
        exit 1
    fi

    if ! command -v rsyslogd >/dev/null 2>&1; then
        say "[ERROR] rsyslogd not found. Install rsyslog first"
        exit 1
    fi

    if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
        say "[ERROR] Interface $INTERFACE not found"
        say "[INFO] Available interfaces:"
        ip -br link
        exit 1
    fi

    check_array_duplicates
}

ensure_firewalld_for_check() {
    if ! systemctl is-enabled --quiet firewalld; then
        mark_fix "firewalld is not enabled"
    fi

    if ! systemctl is-active --quiet firewalld; then
        mark_fix "firewalld is not active"
        say "[INFO] Starting firewalld temporarily for inspection"
        systemctl start firewalld
    fi
}

check_standard() {
    say "=== Checking firewall standard ==="

    if ! zone_exists "$ALLOWED_ZONE"; then
        mark_fix "missing zone: $ALLOWED_ZONE"
    fi

    if ! zone_exists "$ALLOWED_HTTP_ZONE"; then
        mark_fix "missing zone: $ALLOWED_HTTP_ZONE"
    fi

    if ! has_interface "$PUBLIC_ZONE" "$INTERFACE"; then
        mark_fix "$INTERFACE is not assigned to $PUBLIC_ZONE"
    fi

    if [ -n "$(list_sources "$PUBLIC_ZONE")" ]; then
        mark_fix "$PUBLIC_ZONE has sources"
    fi

    if [ -n "$(list_ports "$PUBLIC_ZONE")" ]; then
        mark_fix "$PUBLIC_ZONE has ports"
    fi

    if [ -n "$(list_services "$PUBLIC_ZONE")" ]; then
        mark_fix "$PUBLIC_ZONE has services"
    fi

    if [ -n "$(list_rich_rules "$PUBLIC_ZONE")" ]; then
        mark_fix "$PUBLIC_ZONE has rich rules"
    fi

    if zone_exists "$ALLOWED_ZONE"; then
        local ip
        local port
        local source

        for ip in "${IPS[@]}"; do
            if ! has_source "$ALLOWED_ZONE" "$ip"; then
                mark_fix "missing source in $ALLOWED_ZONE: $ip"
            fi
        done

        for source in $(list_sources "$ALLOWED_ZONE"); do
            if ! contains "$source" "${IPS[@]}"; then
                mark_fix "unexpected source in $ALLOWED_ZONE: $source"
            fi
        done

        for port in "${TCP_PORTS[@]}"; do
            if ! has_port "$ALLOWED_ZONE" "${port}/tcp"; then
                mark_fix "missing port in $ALLOWED_ZONE: ${port}/tcp"
            fi
        done

        for port in "${UDP_PORTS[@]}"; do
            if ! has_port "$ALLOWED_ZONE" "${port}/udp"; then
                mark_fix "missing port in $ALLOWED_ZONE: ${port}/udp"
            fi
        done

        for port in $(list_ports "$ALLOWED_ZONE"); do
            if ! is_allowed_port "$port"; then
                mark_fix "unexpected port in $ALLOWED_ZONE: $port"
            fi
        done

        if [ -n "$(list_rich_rules "$ALLOWED_ZONE")" ]; then
            mark_fix "$ALLOWED_ZONE has rich rules"
        fi
    fi

    if zone_exists "$ALLOWED_HTTP_ZONE"; then
        local ip
        local port
        local source

        for ip in "${HTTP_IPS[@]}"; do
            if ! has_source "$ALLOWED_HTTP_ZONE" "$ip"; then
                mark_fix "missing source in $ALLOWED_HTTP_ZONE: $ip"
            fi
        done

        for source in $(list_sources "$ALLOWED_HTTP_ZONE"); do
            if ! contains "$source" "${HTTP_IPS[@]}"; then
                mark_fix "unexpected source in $ALLOWED_HTTP_ZONE: $source"
            fi
        done

        for port in "${TCP_PORTS[@]}"; do
            if ! has_port "$ALLOWED_HTTP_ZONE" "${port}/tcp"; then
                mark_fix "missing port in $ALLOWED_HTTP_ZONE: ${port}/tcp"
            fi
        done

        for port in "${UDP_PORTS[@]}"; do
            if ! has_port "$ALLOWED_HTTP_ZONE" "${port}/udp"; then
                mark_fix "missing port in $ALLOWED_HTTP_ZONE: ${port}/udp"
            fi
        done

        for port in "${HTTP_EXTRA_TCP_PORTS[@]}"; do
            if ! has_port "$ALLOWED_HTTP_ZONE" "${port}/tcp"; then
                mark_fix "missing port in $ALLOWED_HTTP_ZONE: ${port}/tcp"
            fi
        done

        for port in $(list_ports "$ALLOWED_HTTP_ZONE"); do
            if ! is_allowed_http_port "$port"; then
                mark_fix "unexpected port in $ALLOWED_HTTP_ZONE: $port"
            fi
        done

        if [ -n "$(list_rich_rules "$ALLOWED_HTTP_ZONE")" ]; then
            mark_fix "$ALLOWED_HTTP_ZONE has rich rules"
        fi
    fi

    local source
    for source in $(list_sources trusted); do
        if is_managed_source "$source"; then
            mark_fix "managed source exists in trusted: $source"
        fi
    done

    if [ "$(firewall-cmd --get-log-denied 2>/dev/null || true)" != "unicast" ]; then
        mark_fix "LogDenied is not unicast"
    fi

    if [ ! -f "$RSYSLOG_CONF" ]; then
        mark_fix "missing rsyslog config: $RSYSLOG_CONF"
    fi

    if [ ! -f "$LOGROTATE_CONF" ]; then
        mark_fix "missing logrotate config: $LOGROTATE_CONF"
    fi
}

backup_firewalld() {
    BACKUP_DIR="/root/firewalld.backup.$(date +%F_%H-%M-%S)"
    cp -a /etc/firewalld "$BACKUP_DIR"
    say "[INFO] Backup created: $BACKUP_DIR"
}

protect_ssh_access() {
    local ssh_client_ip=""
    local allowed=0
    local ip
    local ans

    if [ -n "${SSH_CLIENT:-}" ]; then
        ssh_client_ip="${SSH_CLIENT%% *}"
    fi

    if [ -z "$ssh_client_ip" ]; then
        say "[INFO] SSH_CLIENT not found, skipping SSH lockout check"
        return 0
    fi

    say "[INFO] Current SSH client IP: $ssh_client_ip"

    for ip in "${IPS[@]}" "${HTTP_IPS[@]}"; do
        if [ "$ip" = "$ssh_client_ip" ]; then
            allowed=1
            break
        fi
    done

    if [ "$allowed" -eq 1 ]; then
        say "[INFO] Current SSH client IP is allowed"
        return 0
    fi

    say "[WARN] Current SSH client IP $ssh_client_ip is not in standard IP lists"
    say "[WARN] Applying firewall standard may break this SSH session"
    read -p "Add $ssh_client_ip to allowed zone for this run? (y/N): " ans

    if [[ "$ans" =~ ^[Yy]$ ]]; then
        IPS+=("$ssh_client_ip")
        say "[INFO] Added $ssh_client_ip to allowed list for this run"
    else
        say "[ERROR] Stopping to prevent SSH lockout"
        exit 1
    fi
}

remove_all_rich_rules_from_zone() {
    local zone="$1"
    local rule

    while IFS= read -r rule; do
        [ -z "$rule" ] && continue
        firewall-cmd --permanent --zone="$zone" --remove-rich-rule="$rule" >/dev/null 2>&1 || true
        say "[INFO] Removed rich rule from $zone: $rule"
    done < <(list_rich_rules "$zone")
}

apply_standard() {
    say
    say "=== Applying firewall standard ==="

    protect_ssh_access

    if ! systemctl is-enabled --quiet firewalld; then
        systemctl enable firewalld
        say "[INFO] firewalld enabled"
    fi

    if ! systemctl is-active --quiet firewalld; then
        systemctl start firewalld
        say "[INFO] firewalld started"
    fi

    backup_firewalld

    local zone
    local ip
    local source
    local port
    local service

    for zone in "$ALLOWED_ZONE" "$ALLOWED_HTTP_ZONE"; do
        if ! zone_exists "$zone"; then
            firewall-cmd --permanent --new-zone="$zone"
            say "[INFO] Created zone: $zone"
            firewall-cmd --reload
        fi
    done

    if ! has_interface "$PUBLIC_ZONE" "$INTERFACE"; then
        firewall-cmd --permanent --zone="$PUBLIC_ZONE" --add-interface="$INTERFACE" >/dev/null 2>&1 || \
        firewall-cmd --permanent --zone="$PUBLIC_ZONE" --change-interface="$INTERFACE"
        say "[INFO] Assigned $INTERFACE to $PUBLIC_ZONE"
    fi

    # Remove all managed sources from controlled zones first.
    for ip in "${IPS[@]}" "${HTTP_IPS[@]}"; do
        for zone in "$PUBLIC_ZONE" trusted "$ALLOWED_ZONE" "$ALLOWED_HTTP_ZONE"; do
            firewall-cmd --permanent --zone="$zone" --remove-source="$ip" >/dev/null 2>&1 || true
        done
    done

    # Public must not contain any sources.
    for source in $(list_sources "$PUBLIC_ZONE"); do
        firewall-cmd --permanent --zone="$PUBLIC_ZONE" --remove-source="$source" >/dev/null 2>&1 || true
        say "[INFO] Removed source from $PUBLIC_ZONE: $source"
    done

    # Remove unexpected sources from allowed.
    for source in $(list_sources "$ALLOWED_ZONE"); do
        if ! contains "$source" "${IPS[@]}"; then
            firewall-cmd --permanent --zone="$ALLOWED_ZONE" --remove-source="$source" >/dev/null 2>&1 || true
            say "[INFO] Removed unexpected source from $ALLOWED_ZONE: $source"
        fi
    done

    # Remove unexpected sources from allowed_http.
    for source in $(list_sources "$ALLOWED_HTTP_ZONE"); do
        if ! contains "$source" "${HTTP_IPS[@]}"; then
            firewall-cmd --permanent --zone="$ALLOWED_HTTP_ZONE" --remove-source="$source" >/dev/null 2>&1 || true
            say "[INFO] Removed unexpected source from $ALLOWED_HTTP_ZONE: $source"
        fi
    done

    # Add standard sources.
    for ip in "${IPS[@]}"; do
        firewall-cmd --permanent --zone="$ALLOWED_ZONE" --add-source="$ip" >/dev/null 2>&1 || true
    done

    for ip in "${HTTP_IPS[@]}"; do
        firewall-cmd --permanent --zone="$ALLOWED_HTTP_ZONE" --add-source="$ip" >/dev/null 2>&1 || true
    done

    # Public must not contain any ports/services/rich rules.
    for port in $(list_ports "$PUBLIC_ZONE"); do
        firewall-cmd --permanent --zone="$PUBLIC_ZONE" --remove-port="$port" >/dev/null 2>&1 || true
        say "[INFO] Removed port from $PUBLIC_ZONE: $port"
    done

    for service in $(list_services "$PUBLIC_ZONE"); do
        firewall-cmd --permanent --zone="$PUBLIC_ZONE" --remove-service="$service" >/dev/null 2>&1 || true
        say "[INFO] Removed service from $PUBLIC_ZONE: $service"
    done

    remove_all_rich_rules_from_zone "$PUBLIC_ZONE"
    remove_all_rich_rules_from_zone "$ALLOWED_ZONE"
    remove_all_rich_rules_from_zone "$ALLOWED_HTTP_ZONE"

    # Clean ports in allowed.
    for port in $(list_ports "$ALLOWED_ZONE"); do
        if ! is_allowed_port "$port"; then
            firewall-cmd --permanent --zone="$ALLOWED_ZONE" --remove-port="$port" >/dev/null 2>&1 || true
            say "[INFO] Removed unexpected port from $ALLOWED_ZONE: $port"
        fi
    done

    # Clean ports in allowed_http.
    for port in $(list_ports "$ALLOWED_HTTP_ZONE"); do
        if ! is_allowed_http_port "$port"; then
            firewall-cmd --permanent --zone="$ALLOWED_HTTP_ZONE" --remove-port="$port" >/dev/null 2>&1 || true
            say "[INFO] Removed unexpected port from $ALLOWED_HTTP_ZONE: $port"
        fi
    done

    # Add standard ports to allowed.
    for port in "${TCP_PORTS[@]}"; do
        firewall-cmd --permanent --zone="$ALLOWED_ZONE" --add-port="${port}/tcp" >/dev/null 2>&1 || true
    done

    for port in "${UDP_PORTS[@]}"; do
        firewall-cmd --permanent --zone="$ALLOWED_ZONE" --add-port="${port}/udp" >/dev/null 2>&1 || true
    done

    # Add standard ports to allowed_http.
    for port in "${TCP_PORTS[@]}" "${HTTP_EXTRA_TCP_PORTS[@]}"; do
        firewall-cmd --permanent --zone="$ALLOWED_HTTP_ZONE" --add-port="${port}/tcp" >/dev/null 2>&1 || true
    done

    for port in "${UDP_PORTS[@]}"; do
        firewall-cmd --permanent --zone="$ALLOWED_HTTP_ZONE" --add-port="${port}/udp" >/dev/null 2>&1 || true
    done

    if firewall-cmd --set-log-denied=unicast; then
        say "[INFO] LogDenied set to unicast"
    else
        say "[WARN] firewall-cmd failed to set LogDenied, editing firewalld.conf"
        if grep -q '^LogDenied=' /etc/firewalld/firewalld.conf; then
            sed -i 's/^LogDenied=.*/LogDenied=unicast/' /etc/firewalld/firewalld.conf
        else
            echo 'LogDenied=unicast' >> /etc/firewalld/firewalld.conf
        fi
    fi

    cat > "$RSYSLOG_CONF" <<'RSYSLOG_EOF'
# iptables/firewalld logging
:msg, contains, "IN=" -/var/log/firewall.log
& stop
RSYSLOG_EOF

    chmod 0640 "$RSYSLOG_CONF"
    chown root:root "$RSYSLOG_CONF"

    cat > "$LOGROTATE_CONF" <<'LOGROTATE_EOF'
/var/log/firewall.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        /bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
LOGROTATE_EOF

    chmod 0644 "$LOGROTATE_CONF"
    chown root:root "$LOGROTATE_CONF"

    firewall-cmd --reload
    systemctl restart rsyslog

    FIX_DONE=1
}

verify_final() {
    local failed=0
    local ip
    local port
    local source

    say
    say "=== Final verification ==="

    if ! systemctl is-enabled --quiet firewalld; then
        say "[FAIL] firewalld is not enabled"
        failed=1
    else
        say "[OK] firewalld is enabled"
    fi

    if ! systemctl is-active --quiet firewalld; then
        say "[FAIL] firewalld is not active"
        failed=1
    else
        say "[OK] firewalld is active"
    fi

    if ! zone_exists "$ALLOWED_ZONE"; then
        say "[FAIL] missing zone: $ALLOWED_ZONE"
        failed=1
    else
        say "[OK] zone exists: $ALLOWED_ZONE"
    fi

    if ! zone_exists "$ALLOWED_HTTP_ZONE"; then
        say "[FAIL] missing zone: $ALLOWED_HTTP_ZONE"
        failed=1
    else
        say "[OK] zone exists: $ALLOWED_HTTP_ZONE"
    fi

    if ! has_interface "$PUBLIC_ZONE" "$INTERFACE"; then
        say "[FAIL] $INTERFACE is not in $PUBLIC_ZONE"
        failed=1
    else
        say "[OK] $INTERFACE is in $PUBLIC_ZONE"
    fi

    if [ -n "$(firewall-cmd --zone="$PUBLIC_ZONE" --list-sources)" ]; then
        say "[FAIL] $PUBLIC_ZONE sources are not empty"
        failed=1
    else
        say "[OK] $PUBLIC_ZONE sources are empty"
    fi

    if [ -n "$(firewall-cmd --zone="$PUBLIC_ZONE" --list-services)" ]; then
        say "[FAIL] $PUBLIC_ZONE services are not empty"
        failed=1
    else
        say "[OK] $PUBLIC_ZONE services are empty"
    fi

    if [ -n "$(firewall-cmd --zone="$PUBLIC_ZONE" --list-ports)" ]; then
        say "[FAIL] $PUBLIC_ZONE ports are not empty"
        failed=1
    else
        say "[OK] $PUBLIC_ZONE ports are empty"
    fi

    if [ -n "$(firewall-cmd --zone="$PUBLIC_ZONE" --list-rich-rules)" ]; then
        say "[FAIL] $PUBLIC_ZONE rich rules are not empty"
        failed=1
    else
        say "[OK] $PUBLIC_ZONE rich rules are empty"
    fi

    for ip in "${IPS[@]}"; do
        if ! firewall-cmd --zone="$ALLOWED_ZONE" --list-sources | tr ' ' '\n' | grep -Fxq "$ip"; then
            say "[FAIL] missing source in $ALLOWED_ZONE: $ip"
            failed=1
        fi
    done

    for ip in "${HTTP_IPS[@]}"; do
        if ! firewall-cmd --zone="$ALLOWED_HTTP_ZONE" --list-sources | tr ' ' '\n' | grep -Fxq "$ip"; then
            say "[FAIL] missing source in $ALLOWED_HTTP_ZONE: $ip"
            failed=1
        fi
    done

    for source in $(firewall-cmd --zone=trusted --list-sources 2>/dev/null || true); do
        if is_managed_source "$source"; then
            say "[FAIL] managed source still exists in trusted: $source"
            failed=1
        fi
    done

    for port in "${TCP_PORTS[@]}"; do
        if ! firewall-cmd --zone="$ALLOWED_ZONE" --list-ports | tr ' ' '\n' | grep -Fxq "${port}/tcp"; then
            say "[FAIL] missing port in $ALLOWED_ZONE: ${port}/tcp"
            failed=1
        fi
    done

    for port in "${UDP_PORTS[@]}"; do
        if ! firewall-cmd --zone="$ALLOWED_ZONE" --list-ports | tr ' ' '\n' | grep -Fxq "${port}/udp"; then
            say "[FAIL] missing port in $ALLOWED_ZONE: ${port}/udp"
            failed=1
        fi
    done

    for port in "${TCP_PORTS[@]}" "${HTTP_EXTRA_TCP_PORTS[@]}"; do
        if ! firewall-cmd --zone="$ALLOWED_HTTP_ZONE" --list-ports | tr ' ' '\n' | grep -Fxq "${port}/tcp"; then
            say "[FAIL] missing port in $ALLOWED_HTTP_ZONE: ${port}/tcp"
            failed=1
        fi
    done

    for port in "${UDP_PORTS[@]}"; do
        if ! firewall-cmd --zone="$ALLOWED_HTTP_ZONE" --list-ports | tr ' ' '\n' | grep -Fxq "${port}/udp"; then
            say "[FAIL] missing port in $ALLOWED_HTTP_ZONE: ${port}/udp"
            failed=1
        fi
    done

    if [ "$(firewall-cmd --get-log-denied 2>/dev/null || true)" != "unicast" ]; then
        say "[FAIL] LogDenied is not unicast"
        failed=1
    else
        say "[OK] LogDenied is unicast"
    fi

    if [ ! -f "$RSYSLOG_CONF" ]; then
        say "[FAIL] missing rsyslog config: $RSYSLOG_CONF"
        failed=1
    else
        say "[OK] rsyslog config exists"
    fi

    if [ ! -f "$LOGROTATE_CONF" ]; then
        say "[FAIL] missing logrotate config: $LOGROTATE_CONF"
        failed=1
    else
        say "[OK] logrotate config exists"
    fi

    say
    say "=== Active zones ==="
    firewall-cmd --get-active-zones

    say
    say "=== public ==="
    firewall-cmd --zone="$PUBLIC_ZONE" --list-all

    say
    say "=== allowed ports ==="
    firewall-cmd --zone="$ALLOWED_ZONE" --list-ports

    say
    say "=== allowed_http ports ==="
    firewall-cmd --zone="$ALLOWED_HTTP_ZONE" --list-ports

    say
    say "=== LogDenied ==="
    firewall-cmd --get-log-denied || true

    if [ "$failed" -eq 1 ]; then
        say
        say "[ERROR] Final verification failed"
        if [ -n "$BACKUP_DIR" ]; then
            say "[INFO] Backup is here: $BACKUP_DIR"
        fi
        exit 1
    fi

    say
    if [ "$FIX_DONE" -eq 1 ]; then
        say "[SUCCESS] Firewall was fixed and verified successfully"
        say "[INFO] Backup created: $BACKUP_DIR"
    else
        say "[SUCCESS] Firewall already matched the standard. No changes were made"
    fi
}

main() {
    basic_checks
    ensure_firewalld_for_check
    check_standard

    if [ "${CHECK_ONLY:-0}" = "1" ]; then
        if [ "$NEEDS_FIX" -eq 0 ]; then
            say "[OK] Firewall already matches the standard"
            exit 0
        else
            say "[CHECK] Firewall does not match the standard"
            exit 2
        fi
    fi

    if [ "$NEEDS_FIX" -eq 0 ]; then
        say
        say "[OK] Firewall already matches the standard"
        verify_final
        exit 0
    fi

    apply_standard
    verify_final
}

main "$@"
