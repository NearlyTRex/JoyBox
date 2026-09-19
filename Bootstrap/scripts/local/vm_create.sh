#!/usr/bin/env bash

set -euo pipefail

# Creates a throwaway Ubuntu Server VM to rehearse the remote_ubuntu stack against.
#
# Runs on the workstation, not on a server. The VM is a real KVM guest rather than
# a container because the things under test - ufw, a Docker daemon with
# userns-remap, and sshd itself - all need their own kernel-facing stack to mean
# anything.
#
# cloud-init seeds BOTH an authorized key and a console password. That is
# deliberate: init_sshd.sh disables password SSH, and "virsh console" is then the
# only way back in if the key ever stops working.

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

# Defaults
VM_NAME="joybox-test"
VM_USER="${SUDO_USER:-$USER}"
VM_MEMORY="4096"
VM_VCPUS="2"
VM_DISK="20"
VM_RELEASE="noble"
SSH_KEY=""
CONSOLE_PASSWORD="joybox"
IMAGE_DIR="/var/lib/libvirt/images"

# Print usage
print_usage() {
    echo "Usage: $0 [--name NAME] [--user USERNAME] [--ssh-key PATH] [--memory MB]"
    echo "          [--vcpus N] [--disk GB] [--release CODENAME] [--console-password PASS]"
    echo
    echo "Defaults: name=$VM_NAME user=$VM_USER memory=$VM_MEMORY vcpus=$VM_VCPUS disk=${VM_DISK}G release=$VM_RELEASE"
    echo
    echo "Example:"
    echo "  sudo $0 --user alice --ssh-key /home/alice/.ssh/id_ed25519.pub"
    exit 1
}

# Parse arguments
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
        *) break ;;
    esac
done

# Check required tooling
for tool in virt-install virsh qemu-img cloud-localds; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: $tool is not installed."
        echo "Install the workstation prerequisites:"
        echo "  python3 bootstrap.py -a setup -t local_ubuntu --components aptget"
        exit 1
    fi
done

# Resolve the SSH public key
if [[ -z "$SSH_KEY" ]]; then
    for candidate in "/home/$VM_USER/.ssh/id_ed25519.pub" "/home/$VM_USER/.ssh/id_rsa.pub"; do
        if [[ -r "$candidate" ]]; then
            SSH_KEY="$candidate"
            break
        fi
    done
fi
if [[ -z "$SSH_KEY" || ! -r "$SSH_KEY" ]]; then
    echo "Error: no SSH public key found. Generate one first:"
    echo "  ssh-keygen -t ed25519"
    echo "Then pass it with --ssh-key, or place it at /home/$VM_USER/.ssh/id_ed25519.pub"
    exit 1
fi
SSH_KEY_CONTENTS="$(cat "$SSH_KEY")"

# Refuse to clobber an existing VM
if virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
    echo "Error: a VM named '$VM_NAME' already exists."
    echo "Remove it first:  sudo $BASE_DIR/vm_snapshot.sh destroy --name $VM_NAME"
    exit 1
fi

# Fetch the cloud image
BASE_IMAGE="$IMAGE_DIR/${VM_RELEASE}-server-cloudimg-amd64.img"
if [[ ! -f "$BASE_IMAGE" ]]; then
    echo "Downloading the $VM_RELEASE cloud image..."
    mkdir -p "$IMAGE_DIR"
    curl -fL -o "$BASE_IMAGE" \
        "https://cloud-images.ubuntu.com/${VM_RELEASE}/current/${VM_RELEASE}-server-cloudimg-amd64.img"
fi

# Build this VM's disk from the base image
VM_DISK_PATH="$IMAGE_DIR/${VM_NAME}.qcow2"
echo "Creating a ${VM_DISK}G disk at $VM_DISK_PATH..."
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$VM_DISK_PATH" "${VM_DISK}G"

# Build the cloud-init seed
SEED_DIR="$(mktemp -d)"
trap 'rm -rf "$SEED_DIR"' EXIT

cat > "$SEED_DIR/user-data" <<EOF
#cloud-config
hostname: $VM_NAME
users:
  - name: $VM_USER
    groups: [sudo]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: false
    ssh_authorized_keys:
      - $SSH_KEY_CONTENTS
chpasswd:
  list: |
    $VM_USER:$CONSOLE_PASSWORD
  expire: false
# Password SSH stays on for the initial boot so there is a way in before the key
# is confirmed working. init_sshd.sh turns it off as the step being rehearsed.
ssh_pwauth: true
package_update: true
packages:
  - openssh-server
runcmd:
  - [ systemctl, enable, --now, ssh ]
EOF

cat > "$SEED_DIR/meta-data" <<EOF
instance-id: $VM_NAME
local-hostname: $VM_NAME
EOF

SEED_IMAGE="$IMAGE_DIR/${VM_NAME}-seed.iso"
cloud-localds "$SEED_IMAGE" "$SEED_DIR/user-data" "$SEED_DIR/meta-data"

# Make sure the default network is up
if ! virsh net-info default 2>/dev/null | grep -q "Active:.*yes"; then
    echo "Starting the default libvirt network..."
    virsh net-start default 2>/dev/null || true
    virsh net-autostart default 2>/dev/null || true
fi

# Create the VM
echo "Creating VM '$VM_NAME'..."
virt-install \
    --name "$VM_NAME" \
    --memory "$VM_MEMORY" \
    --vcpus "$VM_VCPUS" \
    --disk "path=$VM_DISK_PATH,device=disk,bus=virtio" \
    --disk "path=$SEED_IMAGE,device=cdrom" \
    --os-variant "ubuntu22.04" \
    --network network=default,model=virtio \
    --graphics none \
    --console pty,target_type=serial \
    --import \
    --noautoconsole

# Wait for an address
echo "Waiting for the VM to get an address..."
VM_IP=""
for _ in $(seq 1 60); do
    VM_IP="$(virsh domifaddr "$VM_NAME" 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -n1)"
    if [[ -n "$VM_IP" ]]; then
        break
    fi
    sleep 5
done

if [[ -z "$VM_IP" ]]; then
    echo "Warning: could not determine the VM's address yet."
    echo "Check with: sudo virsh domifaddr $VM_NAME"
    exit 0
fi

echo
echo "VM '$VM_NAME' is up at $VM_IP"
echo
echo "Next:"
echo "  1. sudo $BASE_DIR/hosts_sync.sh --ip $VM_IP"
echo "  2. Put this in ~/JoyBox.local.ini under [UserData.Servers]:"
echo "       server_0_host = $VM_IP"
echo "       server_0_port = 22"
echo "       server_0_user = $VM_USER"
echo "       server_0_key_filepath = ${SSH_KEY%.pub}"
echo "  3. ssh $VM_USER@$VM_IP        (console fallback: sudo virsh console $VM_NAME)"
