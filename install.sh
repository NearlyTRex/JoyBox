#!/usr/bin/env bash
#
# JoyBox installer
# ----------------
# Lowers the barrier to getting JoyBox running on a fresh machine. It installs the
# minimum prerequisites (git + python3), clones (or updates) the repo, then hands off
# to bootstrap.py to do the real work.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/install.sh | bash
#
# Pass arguments straight through to bootstrap.py:
#   curl -fsSL .../install.sh | bash -s -- -a setup -t local_ubuntu --components aptget chrome
#
# With no arguments it defaults to:  bootstrap.py -a setup -t local_ubuntu
#
# Override behaviour with environment variables:
#   JOYBOX_REPO   git URL to clone           (default: https://github.com/NearlyTRex/JoyBox.git)
#   JOYBOX_DIR    where to clone it           (default: $HOME/Repositories/JoyBox)
#   JOYBOX_REF    branch/tag/commit to use    (default: main)
#
# Re-running is safe: an existing checkout is fast-forwarded and bootstrap.py skips
# anything already installed.

set -euo pipefail

JOYBOX_REPO="${JOYBOX_REPO:-https://github.com/NearlyTRex/JoyBox.git}"
JOYBOX_DIR="${JOYBOX_DIR:-$HOME/Repositories/JoyBox}"
JOYBOX_REF="${JOYBOX_REF:-main}"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_BLUE=$'\033[1;34m'; C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'
    C_RED=$'\033[1;31m'; C_RESET=$'\033[0m'
else
    C_BLUE=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_RESET=''
fi
log()  { printf '%s==>%s %s\n' "$C_BLUE"   "$C_RESET" "$*"; }
ok()   { printf '%s==>%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '%swarning:%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%serror:%s %s\n'   "$C_RED"    "$C_RESET" "$*" >&2; exit 1; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------------------
require_apt() {
    if ! has_cmd apt-get; then
        die "This installer supports Ubuntu / Pop!_OS / Linux Mint (apt-based systems). 'apt-get' was not found."
    fi
}

# Pick a privilege-escalation prefix once.
set_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    elif has_cmd sudo; then
        SUDO="sudo"
    else
        die "Need root privileges to install prerequisites, but neither root nor 'sudo' is available."
    fi
}

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
has_pkg() { dpkg -s "$1" >/dev/null 2>&1; }

ensure_prerequisites() {
    local missing=()
    has_cmd git          || missing+=(git)
    has_cmd python3      || missing+=(python3)
    has_pkg python3-venv || missing+=(python3-venv)

    if [ "${#missing[@]}" -eq 0 ]; then
        ok "Prerequisites already present (git, python3, python3-venv)"
        return
    fi

    log "Installing prerequisites: ${missing[*]}"
    $SUDO apt-get update -y
    $SUDO apt-get install -y "${missing[@]}"
}

sync_repo() {
    if [ -d "$JOYBOX_DIR/.git" ]; then
        log "Updating existing checkout at $JOYBOX_DIR"
        git -C "$JOYBOX_DIR" fetch --quiet origin "$JOYBOX_REF"
        git -C "$JOYBOX_DIR" checkout --quiet "$JOYBOX_REF"
        if ! git -C "$JOYBOX_DIR" pull --ff-only --quiet origin "$JOYBOX_REF"; then
            warn "Could not fast-forward $JOYBOX_DIR; leaving your local checkout as-is."
        fi
    elif [ -e "$JOYBOX_DIR" ] && [ -n "$(ls -A "$JOYBOX_DIR" 2>/dev/null)" ]; then
        die "$JOYBOX_DIR exists and is not a git checkout. Move it aside or set JOYBOX_DIR to a different path."
    else
        log "Cloning $JOYBOX_REPO -> $JOYBOX_DIR"
        mkdir -p "$(dirname "$JOYBOX_DIR")"
        git clone --branch "$JOYBOX_REF" "$JOYBOX_REPO" "$JOYBOX_DIR"
    fi
    ok "Repository ready at $JOYBOX_DIR"
}

run_bootstrap() {
    cd "$JOYBOX_DIR"

    local args=("$@")
    if [ "${#args[@]}" -eq 0 ]; then
        args=(-a setup -t local_ubuntu)
    fi

    log "Running: python3 bootstrap.py ${args[*]}"

    # When invoked via 'curl ... | bash', stdin is the script itself, so bootstrap.py's
    # first-run config prompts would hit EOF. Wire them to the terminal when we have one.
    if [ -r /dev/tty ]; then
        python3 bootstrap.py "${args[@]}" < /dev/tty
    else
        warn "No controlling terminal detected; first-run config prompts may fail in this mode."
        python3 bootstrap.py "${args[@]}"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "JoyBox installer"
    require_apt
    set_sudo
    ensure_prerequisites
    sync_repo
    run_bootstrap "$@"
    ok "Done. JoyBox lives at $JOYBOX_DIR"
}

main "$@"
