# ============================================================
# JoyBox Functions
# ============================================================

# Quick access to JoyBox scripts with tab completion awareness
jbrun() {
    local script_name="$1"
    shift
    if [ -x "$HOME/.local/bin/$script_name" ]; then
        "$HOME/.local/bin/$script_name" "$@"
    else
        echo "Script not found: $script_name"
        echo "Available scripts in ~/.local/bin/"
        return 1
    fi
}

# Edit a JoyBox script
jbedit() {
    local script_name="$1"
    local script_path="$JOYBOX_ROOT/Scripts/bin/${script_name}.py"
    if [ -f "$script_path" ]; then
        ${EDITOR:-nano} "$script_path"
    else
        echo "Script not found: $script_path"
        return 1
    fi
}

# Show help for a JoyBox script
jbhelp() {
    local script_name="$1"
    if [ -x "$HOME/.local/bin/$script_name" ]; then
        "$HOME/.local/bin/$script_name" --help
    else
        echo "Script not found: $script_name"
        return 1
    fi
}

# List all available JoyBox scripts
jblist() {
    echo "Available JoyBox scripts:"
    ls -1 "$HOME/.local/bin" 2>/dev/null | grep -v '^\.' | sort
}
