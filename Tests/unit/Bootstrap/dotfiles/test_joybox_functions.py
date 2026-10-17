# Imports
import os
import subprocess
import sys

# Third-party imports
import pytest

pytestmark = pytest.mark.requires_binary("bash", "unshare")

DOTFILES_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "Bootstrap", "dotfiles"))


###########################################################
# JoyBox functions
#
# The functions find the JoyBox commands by asking the venv's Python for the
# console scripts the package installed.
###########################################################

COMMANDS = "backup_tool joybox.cli.backup_tool\nsync_tool joybox.cli.sync_tool\n"
FUNCTIONS = ["joybox_functions.sh"]


# A venv whose Python lists COMMANDS
def fake_venv(sandbox, commands = COMMANDS):
    listing = sandbox.write("/root/.venv/commands.txt", commands)
    sandbox.write("/root/.venv/bin/python3", '#!/bin/bash\ncat > /dev/null\ncat "%s"\n' % listing.replace(
        sandbox.root_dir, ""), mode = 0o755)


# Install a command into the venv that echoes its name and arguments
def fake_command(sandbox, name):
    sandbox.write("/root/.venv/bin/%s" % name, '#!/bin/bash\necho "%s $*"\n' % name, mode = 0o755)


def test_the_commands_are_read_from_the_venvs_console_scripts(shell_traced_env, tmp_path):
    python = tmp_path / ".venv" / "bin" / "python3"
    python.parent.mkdir(parents = True)
    python.write_text('#!/bin/bash\nexec "%s" "$@"\n' % sys.executable)
    python.chmod(0o755)
    script = os.path.join(DOTFILES_DIR, "joybox_functions.sh")
    env = shell_traced_env({"PATH": os.environ["PATH"], "HOME": str(tmp_path)})

    result = subprocess.run(["bash", "-c", 'source "%s"; _jb_commands' % script],
                            env = env, capture_output = True, text = True, check = False)

    assert "backup_tool joybox.cli.backup_tool" in result.stdout.splitlines(), result.stderr
    assert all(line.split()[1].startswith("joybox.cli.") for line in result.stdout.splitlines())


def test_jbrun_runs_a_listed_command_with_its_arguments(shell):
    fake_venv(shell.sandbox)
    fake_command(shell.sandbox, "backup_tool")

    result = shell.source(FUNCTIONS, "jbrun backup_tool --dry-run now")

    assert result.returncode == 0, result.stderr
    assert result.stdout == "backup_tool --dry-run now\n"


def test_jbrun_refuses_a_command_that_is_not_listed(shell):
    fake_venv(shell.sandbox)
    fake_command(shell.sandbox, "pip")

    result = shell.source(FUNCTIONS, "jbrun pip install x")

    assert result.returncode == 1
    assert result.stdout == "Command not found: pip (jblist shows them all)\n"


def test_jbrun_does_not_match_a_command_by_its_prefix(shell):
    fake_venv(shell.sandbox)

    result = shell.source(FUNCTIONS, "jbrun backup")

    assert result.returncode == 1


def test_jbhelp_asks_the_command_for_its_help(shell):
    fake_venv(shell.sandbox)
    fake_command(shell.sandbox, "sync_tool")

    result = shell.source(FUNCTIONS, "jbhelp sync_tool")

    assert result.stdout == "sync_tool --help\n", result.stderr


def test_jbedit_opens_the_module_behind_the_command(shell):
    fake_venv(shell.sandbox)
    shell.sandbox.stub("vim")

    result = shell.source(FUNCTIONS, "jbedit sync_tool", env = {"EDITOR": "vim", "JOYBOX_ROOT": "/srv/joybox"})

    assert result.returncode == 0, result.stderr
    assert shell.sandbox.calls("vim") == [["/srv/joybox/Shared/joybox/cli/sync_tool.py"]]


def test_jbedit_falls_back_to_nano(shell):
    fake_venv(shell.sandbox)
    shell.sandbox.stub("nano")

    shell.source(FUNCTIONS, "jbedit backup_tool", env = {"JOYBOX_ROOT": "/srv/joybox"})

    assert shell.sandbox.calls("nano") == [["/srv/joybox/Shared/joybox/cli/backup_tool.py"]]


def test_jbedit_refuses_a_command_that_is_not_listed(shell):
    fake_venv(shell.sandbox)
    shell.sandbox.stub("nano")

    result = shell.source(FUNCTIONS, "jbedit nothing")

    assert result.returncode == 1
    assert result.stdout == "Command not found: nothing\n"
    assert shell.sandbox.calls("nano") == []


def test_jblist_lists_the_command_names(shell):
    fake_venv(shell.sandbox)

    result = shell.source(FUNCTIONS, "jblist")

    assert result.stdout == "Available JoyBox commands:\nbackup_tool\nsync_tool\n", result.stderr


def test_without_a_venv_nothing_is_listed(shell):
    result = shell.source(FUNCTIONS, "jblist")

    assert result.stdout == "Available JoyBox commands:\n"
    assert result.stderr == ""
