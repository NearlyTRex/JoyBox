#!/usr/bin/env bash

set -euo pipefail

# Lifecycle for the local rehearsal VM. Runs on the workstation.
#
# Subcommand dispatch rather than the init_*.sh shape because this is run
# repeatedly rather than once - create, snapshot before a risky step, revert
# when it goes wrong.

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
VM_NAME="joybox-test"
VM_USER="${SUDO_USER:-$USER}"
VM_MEMORY="4096"
VM_VCPUS="2"
VM_DISK="20"
VM_RELEASE="noble"
SSH_KEY=""
CONSOLE_PASSWORD="joybox"

# Print usage
print_usage() {
    echo "Usage: $0 COMMAND [OPTIONS]"
    echo
    echo "Commands:"
    echo "  create           Create the VM"
    echo "  snapshot LABEL   Take a snapshot called LABEL"
    echo "  revert LABEL     Roll the VM back to LABEL"
    echo "  list             List this VM's snapshots"
    echo "  console          Attach to the serial console (detach with Ctrl+])"
    echo "  ip               Print the VM's address"
    echo "  start | stop     Start or gracefully shut down the VM"
    echo "  destroy          Delete the VM and its disks"
    echo
    echo "Options:"
    echo "  --name NAME              VM name (default: $VM_NAME)"
    echo "  --user USERNAME          Account to create (default: $VM_USER)"
    echo "  --ssh-key PATH           Public key to install (default: the user's id_ed25519.pub)"
    echo "  --memory MB              (default: $VM_MEMORY)"
    echo "  --vcpus N                (default: $VM_VCPUS)"
    echo "  --disk GB                (default: $VM_DISK)"
    echo "  --release CODENAME       (default: $VM_RELEASE)"
    echo "  --console-password PASS  Console fallback password (default: $CONSOLE_PASSWORD)"
    echo
    echo "Examples:"
    echo "  sudo $0 create --user alice"
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
        --user) VM_USER="$2"; shift 2 ;;
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --memory) VM_MEMORY="$2"; shift 2 ;;
        --vcpus) VM_VCPUS="$2"; shift 2 ;;
        --disk) VM_DISK="$2"; shift 2 ;;
        --release) VM_RELEASE="$2"; shift 2 ;;
        --console-password) CONSOLE_PASSWORD="$2"; shift 2 ;;
        -*|--*) echo "Unknown option: $1"; print_usage ;;
        *) ARGS+=("$1"); shift ;;
    esac
done

# Every command but create and destroy needs the VM to exist
if [[ "$COMMAND" != "create" && "$COMMAND" != "destroy" ]]; then
    if ! test_vm_exists "$VM_NAME"; then
        echo "Error: no VM named '$VM_NAME'. Create it with: sudo $0 create"
        exit 1
    fi
fi

# Run command
case "$COMMAND" in
    create)
        create_test_vm "$VM_NAME" "$VM_USER" "$SSH_KEY" "$VM_MEMORY" \
            "$VM_VCPUS" "$VM_DISK" "$VM_RELEASE" "$CONSOLE_PASSWORD"
        ;;
    snapshot)
        if [[ ${#ARGS[@]} -lt 1 ]]; then
            echo "Error: snapshot needs a label."
            print_usage
        fi
        snapshot_test_vm "$VM_NAME" "${ARGS[0]}"
        ;;
    revert)
        if [[ ${#ARGS[@]} -lt 1 ]]; then
            echo "Error: revert needs a label."
            print_usage
        fi
        revert_test_vm "$VM_NAME" "${ARGS[0]}"
        ;;
    list)
        virsh snapshot-list "$VM_NAME"
        ;;
    console)
        echo "Attaching to $VM_NAME. Press Enter for a prompt, Ctrl+] to detach."
        virsh console "$VM_NAME"
        ;;
    ip)
        get_test_vm_ip "$VM_NAME"
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
        destroy_test_vm "$VM_NAME"
        ;;
    *)
        echo "Unknown command: $COMMAND"
        print_usage
        ;;
esac
