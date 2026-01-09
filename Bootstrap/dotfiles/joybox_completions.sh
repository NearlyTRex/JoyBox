# ============================================================
# JoyBox Tab Completions
# ============================================================

# Completion for jbrun function
_jbrun_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local scripts=$(ls "$HOME/.local/bin" 2>/dev/null | grep -v '^\.')
    COMPREPLY=($(compgen -W "$scripts" -- "$cur"))
}
complete -F _jbrun_completions jbrun

# Completion for jbedit function
_jbedit_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local scripts=$(ls "$JOYBOX_ROOT/Scripts/bin"/*.py 2>/dev/null | xargs -n1 basename | sed 's/\.py$//')
    COMPREPLY=($(compgen -W "$scripts" -- "$cur"))
}
complete -F _jbedit_completions jbedit

# Completion for jbhelp function
complete -F _jbrun_completions jbhelp
