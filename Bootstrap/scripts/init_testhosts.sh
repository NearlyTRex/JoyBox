#!/usr/bin/env bash

set -euo pipefail

# Points the test domain and its subdomains at the rehearsal VM by writing a
# marker-bracketed block into the workstation's /etc/hosts.
#
# Runs on the workstation, not on the VM - it is this machine's resolver that
# needs to find joybox.test.

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

# Defaults
DOMAIN="joybox.test"
VM_NAME="joybox-test"
VM_IP=""
REMOVE="false"

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

# Remove and stop
if [[ "$REMOVE" == "true" ]]; then
    remove_test_hosts
    echo "Removed. $DOMAIN no longer resolves locally."
    exit 0
fi

# Resolve the address from libvirt when it was not given
if [[ -z "$VM_IP" ]]; then
    if ! command -v virsh &>/dev/null; then
        echo "Error: --ip was not given and virsh is unavailable."
        exit 1
    fi
    VM_IP="$(get_test_vm_ip "$VM_NAME")"
fi

if [[ -z "$VM_IP" ]]; then
    echo "Error: could not determine the VM's address. Pass it with --ip."
    exit 1
fi

# Write the block
configure_test_hosts "$VM_IP" "$DOMAIN"
