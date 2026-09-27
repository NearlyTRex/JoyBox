#!/usr/bin/env bash
# ============================================================
# JoyBox Tab Completions
# ============================================================

# Completion for jbrun function
_jbrun_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local scripts
    scripts=$(_jb_commands | cut -d' ' -f1)
    mapfile -t COMPREPLY < <(compgen -W "$scripts" -- "$cur")
}
complete -F _jbrun_completions jbrun

# Completion for jbedit function
_jbedit_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local scripts
    scripts=$(_jb_commands | cut -d' ' -f1)
    mapfile -t COMPREPLY < <(compgen -W "$scripts" -- "$cur")
}
complete -F _jbedit_completions jbedit

# Completion for jbhelp function
complete -F _jbrun_completions jbhelp
