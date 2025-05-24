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

# Print usage
print_usage() {
    echo "Usage: $0 --user USERNAME --storage-user STORAGE_USER --storage-host STORAGE_HOST [--remote-path PATH] [--mount-path PATH]"
    echo
    echo "Example:"
    echo "  $0 --user alice --storage-user sb123 --storage-host u123.your-storagebox.de"
    exit 1
}

# Parse arguments
USERNAME=""
STORAGE_USER=""
STORAGE_HOST=""
REMOTE_PATH="/home"
MOUNT_PATH="/mnt/storage"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)
            USERNAME="$2"
            shift 2
            ;;
        --storage-user)
            STORAGE_USER="$2"
            shift 2
            ;;
        --storage-host)
            STORAGE_HOST="$2"
            shift 2
            ;;
        --remote-path)
            REMOTE_PATH="$2"
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

# Validate required args
if [[ -z "$USERNAME" || -z "$STORAGE_USER" || -z "$STORAGE_HOST" ]]; then
    echo "Error: --user, --storage-user, and --storage-host are required."
    print_usage
fi

# Check user
check_user_exists "$USERNAME"

# Call storage box setup
setup_storage_box "$USERNAME" "$STORAGE_USER" "$STORAGE_HOST" "$REMOTE_PATH" "$MOUNT_PATH"
