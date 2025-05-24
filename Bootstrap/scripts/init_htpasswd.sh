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
    cat <<EOF
Usage:
  $0 --action setup --user USERNAME --password PASSWORD
  $0 --action cleanup

Actions:
  setup     Add or update an htpasswd user
  cleanup   Remove the htpasswd file entirely

Options:
  --user USERNAME      Required for setup action
  --password PASSWORD  Required for setup action
EOF
    exit 1
}

# Parse arguments
ACTION=""
USERNAME=""
PASSWORD=""
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
        --password)
            PASSWORD="$2"
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

# Validate arguments based on action
if [[ -z "$ACTION" ]]; then
    echo "Error: --action is required."
    print_usage
fi

# Validate arguments for action
if [[ "$ACTION" == "setup" ]]; then
    if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
        echo "Error: --user and --password are required for setup."
        print_usage
    fi
else
    echo "Error: Invalid action '$ACTION'. Use 'setup' or 'cleanup'."
    print_usage
fi

# Check user
check_user_exists "$USERNAME"

# Run action
if [[ "$ACTION" == "setup" ]]; then
    add_htpasswd_user "$USERNAME" "$PASSWORD"
elif [[ "$ACTION" == "cleanup" ]]; then
    remove_htpasswd
fi
