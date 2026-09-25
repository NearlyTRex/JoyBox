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
    echo "Usage: $0 --user USERNAME"
    exit 1
}

# Parse arguments
USERNAME=""
while [[ $# -gt 0 ]]; do
    case "$1" in
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

# Validate required arg
if [[ -z "$USERNAME" ]]; then
    echo "Error: --user must be specified."
    print_usage
fi

# Check user
check_user_exists "$USERNAME"

# Setup JoyBox
setup_joybox_repo "$USERNAME"
