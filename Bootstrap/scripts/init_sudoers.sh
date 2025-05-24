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
    echo "Usage: $0 --action [setup|cleanup] --user USERNAME"
    exit 1
}

# Parse arguments
ACTION=""
USERNAME=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --action)
            ACTION="$2"
            shift 2
            ;;
        --user)
            USERNAME="$2"
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

# Validate arguments
if [[ -z "$ACTION" || -z "$USERNAME" ]]; then
    echo "Error: Both --action and --user must be specified."
    print_usage
fi

# Check user
check_user_exists "$USERNAME"

# Choose sudoers file path
SUDOERS_FILE="/etc/sudoers.d/99-${USERNAME}-joybox"

# Run action
if [[ "$ACTION" == "setup" ]]; then
    load_packages "$BASE_DIR/serverpackages.txt"
    load_managers "$BASE_DIR/servermanagers.txt"
    install_managers
    setup_sudoers "$USERNAME" "$SUDOERS_FILE"
elif [[ "$ACTION" == "cleanup" ]]; then
    cleanup_sudoers "$SUDOERS_FILE"
else
    echo "Error: Invalid action '$ACTION'. Use 'setup' or 'cleanup'."
    print_usage
fi
