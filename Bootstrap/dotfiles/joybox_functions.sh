# ============================================================
# JoyBox Functions
# ============================================================

# Every installed JoyBox command and its module, one "command module" per line.
# pip installs the commands into the venv from the package's [project.scripts].
_jb_commands() {
    "$HOME/.venv/bin/python3" - 2>/dev/null <<'EOF'
from importlib.metadata import entry_points
for entry in sorted(entry_points(group = "console_scripts"), key = lambda entry: entry.name):
    if entry.value.startswith("joybox.cli."):
        print(entry.name, entry.value.split(":")[0])
EOF
}

# Run a JoyBox command
jbrun() {
    local command_name="$1"
    shift
    if _jb_commands | grep -q "^$command_name "; then
        "$HOME/.venv/bin/$command_name" "$@"
    else
        echo "Command not found: $command_name (jblist shows them all)"
        return 1
    fi
}

# Edit the module behind a JoyBox command
jbedit() {
    local module_name=$(_jb_commands | awk -v name="$1" '$1 == name {print $2}')
    if [ -n "$module_name" ]; then
        ${EDITOR:-nano} "$JOYBOX_ROOT/Shared/${module_name//.//}.py"
    else
        echo "Command not found: $1"
        return 1
    fi
}

# Show help for a JoyBox command
jbhelp() {
    jbrun "$1" --help
}

# List all available JoyBox commands
jblist() {
    echo "Available JoyBox commands:"
    _jb_commands | cut -d' ' -f1
}
