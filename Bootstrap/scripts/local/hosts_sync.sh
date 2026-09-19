#!/usr/bin/env bash

set -euo pipefail

# Points the test domain and its subdomains at the rehearsal VM by writing a
# marker-bracketed block into the workstation's /etc/hosts.
#
# /etc/hosts rather than sslip.io or dnsmasq: the subdomain list is fixed and
# short, this needs no internet access, and it survives the VM's address changing
# across a snapshot revert with one re-run.

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

# Defaults - keep the subdomain list in step with default_settings.py
DOMAIN="joybox.test"
VM_NAME="joybox-test"
VM_IP=""
REMOVE="false"
SUBDOMAINS=(www admin cloud tools tasks audio music aim)

MARKER_BEGIN="# BEGIN JoyBox local testing"
MARKER_END="# END JoyBox local testing"

# Print usage
print_usage() {
    echo "Usage: $0 [--ip ADDRESS] [--domain DOMAIN] [--name VM_NAME] [--remove]"
    echo
    echo "With no --ip, the address is read from the VM named $VM_NAME."
    echo
    echo "Examples:"
    echo "  sudo $0 --ip 192.168.122.42"
    echo "  sudo $0 --remove"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip) VM_IP="$2"; shift 2 ;;
        --domain) DOMAIN="$2"; shift 2 ;;
        --name) VM_NAME="$2"; shift 2 ;;
        --remove) REMOVE="true"; shift ;;
        -*|--*) echo "Unknown option: $1"; print_usage ;;
        *) break ;;
    esac
done

# Drop any previous block; the rewrite path adds a fresh one below
if grep -qF "$MARKER_BEGIN" /etc/hosts; then
    echo "Removing the existing JoyBox block from /etc/hosts..."
    sed -i "/^${MARKER_BEGIN}$/,/^${MARKER_END}$/d" /etc/hosts
fi

if [[ "$REMOVE" == "true" ]]; then
    echo "Removed. $DOMAIN no longer resolves locally."
    exit 0
fi

# Resolve the address from libvirt when it was not given
if [[ -z "$VM_IP" ]]; then
    if ! command -v virsh >/dev/null 2>&1; then
        echo "Error: --ip was not given and virsh is unavailable."
        exit 1
    fi
    VM_IP="$(virsh domifaddr "$VM_NAME" 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -n1)"
fi

if [[ -z "$VM_IP" ]]; then
    echo "Error: could not determine the VM's address. Pass it with --ip."
    exit 1
fi

# Write the block
echo "Pointing $DOMAIN at $VM_IP..."
{
    echo "$MARKER_BEGIN"
    echo "$VM_IP $DOMAIN"
    for sub in "${SUBDOMAINS[@]}"; do
        echo "$VM_IP $sub.$DOMAIN"
    done
    echo "$MARKER_END"
} >> /etc/hosts

echo "Done. Entries added:"
echo "  $DOMAIN"
for sub in "${SUBDOMAINS[@]}"; do
    echo "  $sub.$DOMAIN"
done
