#!/usr/bin/env bash

set -euo pipefail

# Snapshot, revert, console and destroy for the rehearsal VM.
#
# The snapshot/revert pair is what makes the sshd lockout drill safe: take a
# snapshot, run the hardening, and if it locks you out, revert in seconds rather
# than rebuilding. "console" is the recovery path that does not depend on sshd
# working at all.

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

VM_NAME="joybox-test"

# Print usage
print_usage() {
    echo "Usage: $0 COMMAND [--name NAME] [ARGS]"
    echo
    echo "Commands:"
    echo "  snapshot LABEL   Take a snapshot called LABEL"
    echo "  revert LABEL     Roll the VM back to LABEL"
    echo "  list             List this VM's snapshots"
    echo "  console          Attach to the serial console (exit with Ctrl+])"
    echo "  ip               Print the VM's address"
    echo "  start | stop     Start or gracefully shut down the VM"
    echo "  destroy          Delete the VM and its disks"
    echo
    echo "Example:"
    echo "  sudo $0 snapshot pre-sshd"
    echo "  sudo $0 revert pre-sshd"
    exit 1
}

# Parse the command first, then flags
if [[ $# -eq 0 ]]; then
    print_usage
fi
COMMAND="$1"
shift

ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --name) VM_NAME="$2"; shift 2 ;;
        -*|--*) echo "Unknown option: $1"; print_usage ;;
        *) ARGS+=("$1"); shift ;;
    esac
done

# Every command but destroy needs the VM to exist
if ! virsh dominfo "$VM_NAME" >/dev/null 2>&1 && [[ "$COMMAND" != "destroy" ]]; then
    echo "Error: no VM named '$VM_NAME'. Create it with vm_create.sh first."
    exit 1
fi

case "$COMMAND" in
    snapshot)
        if [[ ${#ARGS[@]} -lt 1 ]]; then
            echo "Error: snapshot needs a label."
            print_usage
        fi
        echo "Taking snapshot '${ARGS[0]}' of $VM_NAME..."
        virsh snapshot-create-as "$VM_NAME" "${ARGS[0]}" --atomic
        echo "Revert with: sudo $0 revert ${ARGS[0]}"
        ;;
    revert)
        if [[ ${#ARGS[@]} -lt 1 ]]; then
            echo "Error: revert needs a label."
            print_usage
        fi
        echo "Reverting $VM_NAME to '${ARGS[0]}'..."
        virsh snapshot-revert "$VM_NAME" "${ARGS[0]}" --running
        echo "Reverted. The address may have changed - check with: sudo $0 ip"
        ;;
    list)
        virsh snapshot-list "$VM_NAME"
        ;;
    console)
        echo "Attaching to $VM_NAME. Press Enter for a prompt, Ctrl+] to detach."
        virsh console "$VM_NAME"
        ;;
    ip)
        virsh domifaddr "$VM_NAME" | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -n1
        ;;
    start)
        virsh start "$VM_NAME"
        ;;
    stop)
        virsh shutdown "$VM_NAME"
        ;;
    destroy)
        echo "This deletes VM '$VM_NAME' and all of its disks."
        read -r -p "Type the VM name to confirm: " confirm
        if [[ "$confirm" != "$VM_NAME" ]]; then
            echo "Aborted."
            exit 1
        fi
        virsh destroy "$VM_NAME" 2>/dev/null || true
        virsh undefine "$VM_NAME" --remove-all-storage --snapshots-metadata 2>/dev/null || \
            virsh undefine "$VM_NAME" --remove-all-storage 2>/dev/null || true
        rm -f "/var/lib/libvirt/images/${VM_NAME}-seed.iso"
        echo "Destroyed $VM_NAME."
        ;;
    *)
        echo "Unknown command: $COMMAND"
        print_usage
        ;;
esac
