#!/bin/bash
# Generate the Ghidra decompiler patch from differences between master and dev-testing
#
# Usage: ./generate_patch.sh [GHIDRA_DIR]
#   GHIDRA_DIR defaults to ~/Repositories/Ghidra
#
# The patch is generated from: git diff master...dev-testing
# This captures all changes on dev-testing that aren't in master.

set -e

GHIDRA_DIR="${1:-$HOME/Repositories/Ghidra}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_FILE="$SCRIPT_DIR/ghidra.patch"
BASE_BRANCH="master"
DEV_BRANCH="dev-testing"

if [ ! -d "$GHIDRA_DIR/.git" ]; then
    echo "Error: $GHIDRA_DIR is not a git repository"
    exit 1
fi

cd "$GHIDRA_DIR"

# Verify branches exist
if ! git rev-parse --verify "$BASE_BRANCH" >/dev/null 2>&1; then
    echo "Error: Branch '$BASE_BRANCH' does not exist"
    exit 1
fi

if ! git rev-parse --verify "$DEV_BRANCH" >/dev/null 2>&1; then
    echo "Error: Branch '$DEV_BRANCH' does not exist"
    exit 1
fi

echo "Generating patch from: $GHIDRA_DIR"
echo "Base branch: $BASE_BRANCH"
echo "Dev branch: $DEV_BRANCH"
echo "Output: $PATCH_FILE"

# Generate patch: all changes on dev-testing since it diverged from master
git diff "$BASE_BRANCH...$DEV_BRANCH" > "$PATCH_FILE"

# Check if patch is empty
if [ ! -s "$PATCH_FILE" ]; then
    echo "Warning: No differences between $BASE_BRANCH and $DEV_BRANCH"
    exit 0
fi

echo ""
echo "Patch generated: $PATCH_FILE"
echo "Files included:"
grep "^diff --git" "$PATCH_FILE" | sed 's/diff --git a\//  /' | sed 's/ b\/.*//'
echo ""
echo "Total: $(grep -c "^diff --git" "$PATCH_FILE") files"
