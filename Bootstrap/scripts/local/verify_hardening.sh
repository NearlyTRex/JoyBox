#!/usr/bin/env bash

set -uo pipefail

# Asserts that the hardening actually took effect. Runs ON THE VM (or on a real
# server) as root.
#
# Each check tests the effect, not the configuration: a limit_req directive in
# nginx -T proves nothing if no request is ever refused, and a 127.0.0.1 line in
# a compose file proves nothing if the container published on 0.0.0.0 anyway.
#
# Exit code is the number of failed checks, so it works as a gate in a pipeline.

# Check common functions
BASE_DIR="$(dirname "$0")"
COMMON="$BASE_DIR/../common.sh"
if [[ ! -r "$COMMON" ]]; then
    echo "Error: Cannot find or read $COMMON"
    exit 1
fi

# Load common functions
source "$COMMON"
ensure_bash_shell
ensure_root_user

DOMAIN="joybox.test"
FAILURES=0

# Print usage
print_usage() {
    echo "Usage: $0 [--domain DOMAIN]"
    echo
    echo "Runs on the target server. Reports PASS/FAIL per check and exits with"
    echo "the number of failures."
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        -*|--*) echo "Unknown option: $1"; print_usage ;;
        *) break ;;
    esac
done

pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAILURES=$((FAILURES + 1)); }
skip() { echo "  SKIP  $1"; }
section() { echo; echo "== $1"; }

# 1. Every published container port must be on loopback
section "Container port bindings"
if ! command -v docker >/dev/null 2>&1; then
    skip "docker is not installed"
else
    exposed="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0|\[::\]' || true)"
    if [[ -z "$exposed" ]]; then
        pass "no container publishes on 0.0.0.0"
    else
        fail "containers published on all interfaces:"
        echo "$exposed" | sed 's/^/          /'
    fi
fi

# ss is the second opinion: it sees the actual listening socket, not docker's view
if command -v ss >/dev/null 2>&1; then
    wild="$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -E '^(0\.0\.0\.0|\*|\[::\]):' | grep -vE ':(22|80|443)$' || true)"
    if [[ -z "$wild" ]]; then
        pass "no unexpected wildcard listeners (only 22/80/443)"
    else
        fail "unexpected wildcard listeners:"
        echo "$wild" | sed 's/^/          /'
    fi
fi

# 2. Firewall scope
section "Firewall"
if ! command -v ufw >/dev/null 2>&1; then
    skip "ufw is not installed"
elif ! ufw status 2>/dev/null | grep -q "Status: active"; then
    fail "ufw is installed but not active"
else
    pass "ufw is active"
    echo "        allowed:"
    ufw status | awk '/ALLOW/ {print "          " $0}'
fi

# 3. sshd hardening
section "sshd"
if ! command -v sshd >/dev/null 2>&1; then
    skip "sshd is not installed"
else
    sshd_config="$(sshd -T 2>/dev/null || true)"
    if [[ -z "$sshd_config" ]]; then
        fail "could not read the effective sshd config"
    else
        if echo "$sshd_config" | grep -qi "^passwordauthentication no"; then
            pass "password authentication is disabled"
        else
            fail "password authentication is still enabled"
        fi
        if echo "$sshd_config" | grep -qiE "^permitrootlogin (no|prohibit-password)"; then
            pass "root login is restricted"
        else
            fail "root login is not restricted"
        fi
    fi
fi

# 4. fail2ban jails - the sshd jail silently matches nothing on 24.04+ unless
# it is told to read journald, so assert it is actually running
section "fail2ban"
if ! command -v fail2ban-client >/dev/null 2>&1; then
    skip "fail2ban is not installed"
else
    for jail in sshd nginx-http-auth; do
        if fail2ban-client status "$jail" >/dev/null 2>&1; then
            pass "jail '$jail' is running"
        else
            fail "jail '$jail' is not running"
        fi
    done
fi

# 5. Docker daemon hardening
section "Docker daemon"
if [[ ! -f /etc/docker/daemon.json ]]; then
    skip "no /etc/docker/daemon.json"
else
    for key in userns-remap no-new-privileges; do
        if grep -q "$key" /etc/docker/daemon.json; then
            pass "$key is configured"
        else
            fail "$key is missing"
        fi
    done
    # Configured is not the same as active: under userns-remap the daemon runs
    # containers as a remapped subuid, so the remap root must not be host uid 0.
    if command -v docker >/dev/null 2>&1; then
        remap_uid="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+$' || true)"
        if [[ -n "$remap_uid" ]]; then
            pass "userns-remap is active (root dir suffix $remap_uid)"
        else
            fail "userns-remap does not appear active - DockerRootDir has no uid suffix"
        fi
    fi
fi

# 6. Rate limiting must actually refuse requests
section "Rate limiting"
if ! command -v nginx >/dev/null 2>&1; then
    skip "nginx is not installed"
else
    nginx_config="$(nginx -T 2>/dev/null || true)"
    if echo "$nginx_config" | grep -q "limit_req_zone"; then
        pass "limit_req_zone is defined"
    else
        fail "limit_req_zone is missing"
    fi
    if echo "$nginx_config" | grep -qE "^\s*limit_req\s+zone="; then
        pass "limit_req consumes the zone"
    else
        fail "limit_req is missing - the zone is defined but never applied"
    fi
    if echo "$nginx_config" | grep -q "server_tokens off"; then
        pass "server_tokens is off"
    else
        fail "server_tokens is not off"
    fi

    # Burst past the configured rate and expect nginx to start refusing
    if command -v curl >/dev/null 2>&1; then
        refused=0
        for _ in $(seq 1 40); do
            code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "https://$DOMAIN/" 2>/dev/null || echo 000)"
            if [[ "$code" == "503" ]]; then
                refused=$((refused + 1))
            fi
        done
        if [[ "$refused" -gt 0 ]]; then
            pass "a 40-request burst was rate limited ($refused refused)"
        else
            fail "a 40-request burst was never rate limited"
        fi
    fi
fi

# 7. Unattended upgrades must be able to take effect
section "Unattended upgrades"
if [[ -f /etc/apt/apt.conf.d/52-joybox-unattended ]]; then
    pass "JoyBox unattended-upgrades config is present"
    if grep -q 'Automatic-Reboot "true"' /etc/apt/apt.conf.d/52-joybox-unattended; then
        pass "automatic reboot is enabled"
    else
        fail "automatic reboot is not enabled - kernel updates install but never activate"
    fi
else
    fail "no /etc/apt/apt.conf.d/52-joybox-unattended"
fi

# Summary
echo
if [[ "$FAILURES" -eq 0 ]]; then
    echo "All checks passed."
else
    echo "$FAILURES check(s) failed."
fi
exit "$FAILURES"
