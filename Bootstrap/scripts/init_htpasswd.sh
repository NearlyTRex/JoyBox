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
  --password PASSWORD  Optional for setup; prompted for if omitted, which keeps
                       it out of ps output and shell history
  --password-file PATH Optional for setup; read the password from a file, for
                       unattended runs
EOF
    exit 1
}

# Parse arguments
ACTION=""
USERNAME=""
PASSWORD=""
PASSWORD_FILE=""
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
        --password-file)
            PASSWORD_FILE="$2"
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
    if [[ -z "$USERNAME" ]]; then
        echo "Error: --user is required for setup."
        print_usage
    fi

    if [[ -n "$PASSWORD_FILE" ]]; then
        if [[ ! -r "$PASSWORD_FILE" ]]; then
            echo "Error: cannot read $PASSWORD_FILE."
            exit 1
        fi
        PASSWORD="$(cat "$PASSWORD_FILE")"
        if [[ -z "$PASSWORD" ]]; then
            echo "Error: $PASSWORD_FILE is empty."
            exit 1
        fi
    fi

    # Prefer prompting over --password: an argument is visible in ps for the
    # lifetime of the process and is written to the invoking shell's history.
    if [[ -z "$PASSWORD" ]]; then
        read -r -s -p "Password for $USERNAME: " PASSWORD
        echo
        read -r -s -p "Confirm password: " PASSWORD_CONFIRM
        echo
        if [[ "$PASSWORD" != "$PASSWORD_CONFIRM" ]]; then
            echo "Error: passwords do not match."
            exit 1
        fi
        if [[ -z "$PASSWORD" ]]; then
            echo "Error: password cannot be empty."
            exit 1
        fi
    fi
else
    echo "Error: Invalid action '$ACTION'. Use 'setup' or 'cleanup'."
    print_usage
fi

# Run action
if [[ "$ACTION" == "setup" ]]; then
    add_htpasswd_user "$USERNAME" "$PASSWORD"
elif [[ "$ACTION" == "cleanup" ]]; then
    remove_htpasswd
fi
