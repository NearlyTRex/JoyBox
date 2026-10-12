# Third-party imports
import pytest


###########################################################
# JoyBox completions
###########################################################

DOTFILES = ["joybox_functions.sh", "joybox_completions.sh"]
COMMANDS = "backup_tool joybox.cli.backup_tool\nbackup_tool_extra joybox.cli.backup_tool_extra\nsync_tool joybox.cli.sync_tool\n"


@pytest.fixture
def completing(shell):
    listing = shell.sandbox.write("/root/.venv/commands.txt", COMMANDS)
    shell.sandbox.write("/root/.venv/bin/python3", '#!/bin/bash\ncat > /dev/null\ncat "%s"\n' % listing.replace(
        shell.sandbox.root_dir, ""), mode = 0o755)
    return shell


# Complete the last word of a command line with the function bash would call
def complete(shell, function, *words):
    body = "COMP_WORDS=(%s)\nCOMP_CWORD=%d\n%s\nprintf '%%s\\n' \"${COMPREPLY[@]}\"" % (
        " ".join("'%s'" % word for word in words), len(words) - 1, function)
    return shell.source(DOTFILES, body)


@pytest.mark.parametrize("command, function", [
    ("jbrun", "_jbrun_completions"),
    ("jbedit", "_jbedit_completions"),
    ("jbhelp", "_jbrun_completions"),
])
def test_each_function_completes_with_its_own_completer(shell, command, function):
    result = shell.source(DOTFILES, "complete -p %s" % command)

    assert result.stdout == "complete -F %s %s\n" % (function, command), result.stderr


@pytest.mark.parametrize("function", ["_jbrun_completions", "_jbedit_completions"])
def test_a_partial_name_completes_to_the_commands_it_starts(completing, function):
    result = complete(completing, function, "jbrun", "backup")

    assert result.stdout == "backup_tool\nbackup_tool_extra\n", result.stderr


@pytest.mark.parametrize("function", ["_jbrun_completions", "_jbedit_completions"])
def test_an_empty_word_completes_to_every_command(completing, function):
    result = complete(completing, function, "jbedit", "")

    assert result.stdout == "backup_tool\nbackup_tool_extra\nsync_tool\n", result.stderr


def test_a_name_nothing_starts_with_completes_to_nothing(completing):
    result = complete(completing, "_jbrun_completions", "jbrun", "zzz")

    assert result.stdout == "\n", result.stderr
