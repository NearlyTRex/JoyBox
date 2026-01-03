#!/bin/bash
# Generate the Ghidra decompiler patch from all current changes
#
# Usage: ./generate_ebp_patch.sh [GHIDRA_DIR]
#   GHIDRA_DIR defaults to ~/Repositories/Ghidra

set -e

GHIDRA_DIR="${1:-$HOME/Repositories/Ghidra}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_FILE="$SCRIPT_DIR/ghidra.patch"

if [ ! -d "$GHIDRA_DIR/.git" ]; then
    echo "Error: $GHIDRA_DIR is not a git repository"
    exit 1
fi

echo "Generating patch from: $GHIDRA_DIR"
echo "Output: $PATCH_FILE"

cd "$GHIDRA_DIR"

# Stage any new (untracked) files so they appear in diff
# This uses intent-to-add (-N) which stages the file path without content
git status --porcelain | grep '^??' | cut -c4- | while read -r file; do
    git add -N "$file" 2>/dev/null || true
done

# Generate patch for all modified and new files
git diff > "$PATCH_FILE"

# Check if patch is empty
if [ ! -s "$PATCH_FILE" ]; then
    echo "Warning: No changes detected, patch file is empty"
    exit 0
fi

echo "Patch generated: $PATCH_FILE"
echo "Files included:"
grep "^diff --git" "$PATCH_FILE" | sed 's/diff --git a\//  /' | sed 's/ b\/.*//'
echo ""
echo "Total: $(grep -c "^diff --git" "$PATCH_FILE") files"
