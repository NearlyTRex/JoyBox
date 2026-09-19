#!/usr/bin/env bash

set -euo pipefail

# Stands in for the Hetzner Storage Box on the rehearsal VM.
#
# Runs ON THE VM, not the workstation. Everything downstream - Navidrome's music
# dir, Audiobookshelf's library, backup_root - just wants a path with files under
# it, so a plain directory is enough and a loopback image would add ceremony for
# no extra coverage.
#
# Known gap, stated rather than faked: this does not exercise sshfs itself -
# mount flags, idmap, _netdev ordering, or off-box durability.

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
        --user) USERNAME="$2"; shift 2 ;;
        --mount-path) MOUNT_PATH="$2"; shift 2 ;;
        -*|--*) echo "Unknown option: $1"; print_usage ;;
        *) break ;;
    esac
done

# Validate required arg
if [[ -z "$USERNAME" ]]; then
    echo "Error: --user must be specified."
    print_usage
fi

# Check user
check_user_exists "$USERNAME"

# Create the layout the components expect
echo "Creating local storage at $MOUNT_PATH..."
mkdir -p "$MOUNT_PATH/Music/Audiobook"
mkdir -p "$MOUNT_PATH/Backups"
chown -R "$USERNAME":"$USERNAME" "$MOUNT_PATH"

# Seed placeholder media so library scans have something to find. Silence is
# fine - the point is that the scanners see a real file, not that it plays.
if command -v ffmpeg >/dev/null 2>&1; then
    if [[ ! -f "$MOUNT_PATH/Music/placeholder.mp3" ]]; then
        echo "Generating placeholder media with ffmpeg..."
        ffmpeg -loglevel error -f lavfi -i anullsrc=r=44100:cl=mono -t 2 \
            -metadata title="JoyBox Test Track" \
            -metadata artist="JoyBox" \
            -metadata album="Local Testing" \
            "$MOUNT_PATH/Music/placeholder.mp3"
        cp "$MOUNT_PATH/Music/placeholder.mp3" "$MOUNT_PATH/Music/Audiobook/placeholder.mp3"
        chown -R "$USERNAME":"$USERNAME" "$MOUNT_PATH/Music"
    fi
else
    echo "Note: ffmpeg is not installed, so no placeholder media was created."
    echo "The directories exist, but the library scanners will find them empty."
fi

echo
echo "Local storage ready:"
find "$MOUNT_PATH" -maxdepth 2 | sed 's/^/  /'
