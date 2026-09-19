#!/usr/bin/env bash

set -euo pipefail

# Stands in for the Hetzner Storage Box on the rehearsal VM, so the components
# that read /mnt/storage behave the same way they would on a real server.
#
# Runs on the VM. The real thing is init_storagebox.sh.

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
USERNAME=""
MOUNT_PATH="/mnt/storage"

# Print usage
print_usage() {
    echo "Usage: $0 --user USERNAME [--mount-path PATH]"
    echo
    echo "Example:"
    echo "  sudo $0 --user alice"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)
            USERNAME="$2"
            shift 2
            ;;
        --mount-path)
            MOUNT_PATH="$2"
            shift 2
            ;;
        -*|--*)
            echo "Unknown option: $1"
            print_usage
            ;;
        *)
            break
            ;;
    esac
done

# Validate required arg
if [[ -z "$USERNAME" ]]; then
    echo "Error: --user must be specified."
    print_usage
fi

# Check user
check_user_exists "$USERNAME"

# Create the local storage layout
setup_local_storage "$USERNAME" "$MOUNT_PATH"
