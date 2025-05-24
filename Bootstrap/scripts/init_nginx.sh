#!/usr/bin/env bash

set -euo pipefail

# Check common functions
BASE_DIR="$(dirname "$0")"
if [[ ! -r "$BASE_DIR/common.sh" ]]; then
    echo "Error: Cannot find or read $BASE_DIR/common.sh"
    exit 1
fi

# Load common functions
source "$BASE_DIR/common.sh"
ensure_bash_shell
ensure_root_user

# Setup nginx
configure_unattended_upgrades
configure_ufw_firewall
configure_fail2ban
configure_security_headers
configure_rate_limit
configure_modsecurity
