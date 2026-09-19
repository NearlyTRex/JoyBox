#!/usr/bin/env bash

# Note: no "set -e" - a failing check is data, not a reason to stop. The exit
# code is the number of failures, so this works as a gate in a pipeline.
set -uo pipefail

# Asserts that the hardening actually took effect. Runs on the target, whether
# that is the rehearsal VM or a real server.
#
# Individual checks are available as verify_* functions in common.sh if you want
# to run just one.

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

# Print usage
print_usage() {
    echo "Usage: $0 [--domain DOMAIN]"
    echo
    echo "Reports PASS/FAIL per check and exits with the number of failures."
    echo
    echo "Example:"
    echo "  sudo $0 --domain joybox.test"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)
            DOMAIN="$2"
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

# Run every check
verify_hardening "$DOMAIN"
exit $?
