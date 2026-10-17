# Imports
import os
import subprocess

# Third-party imports
import pytest

pytestmark = pytest.mark.requires_binary("bash", "unshare")

DOTFILES_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "Bootstrap", "dotfiles"))


###########################################################
# Shell configuration
###########################################################

SHELL = ["shell.sh"]


def test_history_is_kept_long_and_appended(shell):
    result = shell.source(SHELL, 'echo "$HISTCONTROL $HISTSIZE $HISTFILESIZE $HISTTIMEFORMAT"\nshopt -p histappend cmdhist')

    assert result.stdout == "ignoreboth:erasedups 10000 20000 %F %T \nshopt -s histappend\nshopt -s cmdhist\n", result.stderr


def test_the_shell_options_are_set(shell):
    result = shell.source(SHELL, "shopt -p checkwinsize globstar nocaseglob cdspell autocd")

    assert result.returncode == 0, result.stderr
    assert all(line.startswith("shopt -s ") for line in result.stdout.splitlines())


def test_sourcing_prints_nothing(shell):
    result = shell.source(SHELL)

    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")


###########################################################
# Prompt
###########################################################

def test_the_prompt_shows_the_git_branch(shell):
    shell.sandbox.stub("git", stdout = "  main\n* dev/feature\n")

    result = shell.source(SHELL, 'echo "[$(__git_branch)]"')

    assert result.stdout == "[ (dev/feature)]\n", result.stderr
    assert shell.sandbox.calls("git") == [["branch"]]


def test_outside_a_repository_the_branch_is_empty(shell):
    shell.sandbox.stub("git", code = 128)

    result = shell.source(SHELL, 'echo "[$(__git_branch)]"')

    assert result.stdout == "[]\n"


def test_the_prompt_asks_for_the_branch_each_time_it_is_drawn(shell):
    result = shell.source(SHELL, 'echo "$PS1"')

    assert "\\u" in result.stdout and "\\w" in result.stdout
    assert "$(__git_branch)" in result.stdout


def test_root_gets_a_red_user_name(shell):
    result = shell.source(SHELL, 'echo "$PS1"')

    assert result.stdout.startswith("\\[\\033[1;31m\\]\\u"), result.stdout


def test_other_users_get_a_green_one(shell_traced_env, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("needs a user other than root")
    script = os.path.join(DOTFILES_DIR, "shell.sh")
    env = shell_traced_env({"PATH": os.environ["PATH"], "HOME": str(tmp_path)})

    result = subprocess.run(["bash", "-c", 'source "%s"; echo "$PS1"' % script],
                            env = env, capture_output = True, text = True, check = False)

    assert result.stdout.startswith("\\[\\033[1;32m\\]\\u"), result.stdout


###########################################################
# PATH and aliases
###########################################################

def test_the_joybox_bin_comes_first(shell):
    result = shell.source(SHELL, 'echo "$PATH"')

    assert result.stdout.startswith("/root/.joybox/bin:")
    assert ".venv" not in result.stdout


def test_the_venv_bin_comes_last_when_there_is_one(shell):
    os.makedirs(shell.sandbox.host_path("/root/.venv/bin"))

    result = shell.source(SHELL, 'echo "$PATH"')

    assert result.stdout.startswith("/root/.joybox/bin:")
    assert result.stdout.endswith(":/root/.venv/bin\n")


def test_colored_output_is_asked_for(shell):
    result = shell.source(SHELL, 'echo "$CLICOLOR $LSCOLORS"\nalias ls grep diff')

    assert result.stdout.splitlines() == [
        "1 ExGxBxDxCxEgEdxbxgxcxd",
        "alias ls='ls --color=auto'",
        "alias grep='grep --color=auto'",
        "alias diff='diff --color=auto'",
    ]


@pytest.mark.parametrize("name, expansion", [
    ("ll", "ls -alF"), ("la", "ls -A"), ("l", "ls -CF"),
    ("..", "cd .."), ("...", "cd ../.."), ("....", "cd ../../.."),
    ("mkdir", "mkdir -pv"), ("rm", "rm -i"), ("cp", "cp -i"), ("mv", "mv -i"),
    ("fgrep", "fgrep --color=auto"), ("egrep", "egrep --color=auto"),
])
def test_the_common_aliases(shell, name, expansion):
    result = shell.source(SHELL, "alias -- %s" % name)

    assert result.stdout == "alias %s='%s'\n" % (name, expansion), result.stderr


###########################################################
# Functions
###########################################################

def test_mkcd_makes_a_directory_and_enters_it(shell):
    result = shell.source(SHELL, "mkcd /tmp/one/two\npwd")

    assert result.stdout == "/tmp/one/two\n", result.stderr
    assert os.path.isdir(shell.sandbox.host_path("/tmp/one/two"))


def test_mkcd_fails_when_the_directory_cannot_be_made(shell):
    shell.sandbox.write("/tmp/file", "")

    result = shell.source(SHELL, "mkcd /tmp/file/sub || echo failed\npwd")

    assert result.stdout.splitlines() == ["failed", "/root"]


@pytest.mark.parametrize("name, command", [
    ("a.tar.bz2", ["tar", "xjf"]),
    ("a.tar.gz", ["tar", "xzf"]),
    ("a.tar.xz", ["tar", "xJf"]),
    ("a.bz2", ["bunzip2"]),
    ("a.rar", ["unrar", "x"]),
    ("a.gz", ["gunzip"]),
    ("a.tar", ["tar", "xf"]),
    ("a.tbz2", ["tar", "xjf"]),
    ("a.tgz", ["tar", "xzf"]),
    ("a.zip", ["unzip"]),
    ("a.Z", ["uncompress"]),
    ("a.7z", ["7z", "x"]),
])
def test_extract_uses_the_tool_for_the_archive_type(shell, name, command):
    for tool in ["tar", "bunzip2", "unrar", "gunzip", "unzip", "uncompress", "7z"]:
        shell.sandbox.stub(tool)
    shell.sandbox.write("/root/%s" % name, "")

    result = shell.source(SHELL, "extract %s" % name)

    assert result.returncode == 0, result.stderr
    assert [[call[0]] + call[1:] for call in shell.sandbox.calls() if call[0] == command[0]] == [command + [name]]


def test_extract_names_a_file_it_cannot_extract(shell):
    shell.sandbox.write("/root/notes.txt", "")

    result = shell.source(SHELL, "extract notes.txt")

    assert result.stdout == "'notes.txt' cannot be extracted via extract()\n"


def test_extract_names_a_file_that_is_not_there(shell):
    result = shell.source(SHELL, "extract missing.zip")

    assert result.stdout == "'missing.zip' is not a valid file\n"
