#!/bin/bash
# Safe launcher for /opt/setup-firewall-standard-core.sh
# Preflight -> auto-fix permissions -> detect interface -> confirmation -> run core standardizer

set -euo pipefail
IFS=$'\n\t'

SELF="/opt/setup-firewall-standard.sh"
CORE="/opt/setup-firewall-standard-core.sh"
CONFIG_FILE="${CONFIG_FILE:-/etc/firewall-standard.conf}"
OPT_DIR="/opt"

CRITICAL_FAILED=0
WARNINGS=0

say() {
    echo "$@"
}

fail() {
    say "[CRITICAL] $1"
    CRITICAL_FAILED=1
}

warn() {
    say "[WARN] $1"
    WARNINGS=1
}

get_default_interface() {
    ip route show default 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}'
}

fix_owner_mode() {
    local path="$1"
    local owner="$2"
    local mode="$3"

    if [ ! -e "$path" ]; then
        fail "Path not found: $path"
        return 1
    fi

    current_owner=$(stat -c '%U:%G' "$path" 2>/dev/null || echo unknown)
    current_mode=$(stat -c '%a' "$path" 2>/dev/null || echo unknown)

    if [ "$current_owner" != "$owner" ]; then
        say "[FIX] chown $owner $path"
        chown "$owner" "$path" || {
            fail "Failed to chown $path"
            return 1
        }
    fi

    current_mode=$(stat -c '%a' "$path" 2>/dev/null || echo unknown)

    if [ "$current_mode" != "$mode" ]; then
        say "[FIX] chmod $mode $path"
        chmod "$mode" "$path" || {
            fail "Failed to chmod $path"
            return 1
        }
    fi
}

is_ip_in_core_lists() {
    local ip="$1"

    awk '
        /^IPS=\(/ {in_ips=1; next}
        /^HTTP_IPS=\(/ {in_http=1; next}
        /^\)/ {in_ips=0; in_http=0; next}
        (in_ips || in_http) && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1}
    ' "$CONFIG_FILE" | grep -Fxq "$ip"
}

say "=== Preflight ==="

if [ "$EUID" -ne 0 ]; then
    fail "Run as root"
    say
    say "[ERROR] Critical preflight checks failed. No firewall changes were made."
    exit 1
fi

say
say "+ bash -n $SELF && echo \"Syntax OK\""
if bash -n "$SELF"; then
    say "Syntax OK"
else
    fail "Launcher script has syntax errors: $SELF"
fi

say
say "+ ls -l $SELF"
ls -l "$SELF" || fail "Cannot stat launcher script: $SELF"

say
say "+ ip -br link"
if command -v ip >/dev/null 2>&1; then
    ip -br link || fail "Cannot list network interfaces"
else
    fail "ip command not found"
fi

say
say '+ echo "$SSH_CLIENT"'
say "${SSH_CLIENT:-}"

say
say "+ bash -n $CORE && echo \"Core Syntax OK\""
if [ ! -f "$CORE" ]; then
    fail "Core script not found: $CORE"
elif bash -n "$CORE"; then
    say "Core Syntax OK"
else
    fail "Core script has syntax errors: $CORE"
fi

say
say "=== Auto-fix permissions ==="

fix_owner_mode "$OPT_DIR" "root:root" "755"
fix_owner_mode "$SELF" "root:root" "750"

if [ -f "$CORE" ]; then
    fix_owner_mode "$CORE" "root:root" "750"
fi

if ! command -v firewall-cmd >/dev/null 2>&1; then
    fail "firewall-cmd not found. Install firewalld"
fi

if ! command -v rsyslogd >/dev/null 2>&1; then
    fail "rsyslogd not found. Install rsyslog"
fi

DETECTED_INTERFACE="${INTERFACE:-}"

if [ -z "$DETECTED_INTERFACE" ]; then
    DETECTED_INTERFACE="$(get_default_interface || true)"
fi

if [ -z "$DETECTED_INTERFACE" ]; then
    fail "Could not detect default network interface"
else
    say "[INFO] Interface selected: $DETECTED_INTERFACE"

    if ! ip link show "$DETECTED_INTERFACE" >/dev/null 2>&1; then
        fail "Selected interface does not exist: $DETECTED_INTERFACE"
    fi
fi

if [ -n "${SSH_CLIENT:-}" ]; then
    SSH_CLIENT_IP="${SSH_CLIENT%% *}"
    say "[INFO] SSH client IP: $SSH_CLIENT_IP"

    if [ -f "$CORE" ]; then
        if is_ip_in_core_lists "$SSH_CLIENT_IP"; then
            say "[OK] SSH client IP is present in standard IP lists"
        else
            fail "SSH client IP $SSH_CLIENT_IP is not present in IPS or HTTP_IPS"
        fi
    fi
else
    warn "SSH_CLIENT is empty. Probably not running over SSH, or SSH client cannot be checked"
fi

if [ "$CRITICAL_FAILED" -eq 1 ]; then
    say
    say "=== Recommendations ==="
    say "1. Check interface with: ip route | grep default"
    say "2. Run with explicit interface if needed: INTERFACE=ens192 $SELF"
    say "3. Add your SSH client IP to IPS or HTTP_IPS before applying firewall standard"
    say "4. Check files:"
    say "   ls -ld /opt"
    say "   ls -l $SELF $CORE"
    say "5. Then retry: $SELF"
    say
    say "[ERROR] Critical preflight checks failed. No firewall changes were made."
    exit 1
fi

if [ "$WARNINGS" -eq 1 ]; then
    say
    say "[WARN] Non-critical warnings were found. You can continue, but review them."
fi

say
say
say "=== Firewall standard check ==="

if INTERFACE="$DETECTED_INTERFACE" CONFIG_FILE="$CONFIG_FILE" CHECK_ONLY=1 "$CORE"; then
    say
    say "[SUCCESS] Firewall already matches the standard. No changes are required."
    say "[INFO] Core standardizer was not started in fix mode."
    exit 0
else
    check_rc=$?

    if [ "$check_rc" -eq 2 ]; then
        say
        say "[INFO] Firewall differs from the standard."
        say "[INFO] Fix mode is required to apply changes."
    else
        fail "Firewall check failed with exit code: $check_rc"
    fi
fi

if [ "$CRITICAL_FAILED" -eq 1 ]; then
    say
    say "[ERROR] Critical preflight checks failed. No firewall changes were made."
    exit 1
fi

read -p "Continue and run firewall standardizer? (y/N): " ans

if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    say "[INFO] Cancelled by user. No firewall changes were made."
    exit 0
fi

say
say "=== Running firewall standardizer ==="
INTERFACE="$DETECTED_INTERFACE" CONFIG_FILE="$CONFIG_FILE" "$CORE"
