# Third-party imports
import pytest

pytestmark = pytest.mark.requires_binary("bash", "unshare")


###########################################################
# JoyBox aliases
###########################################################

@pytest.mark.parametrize("name, expansion", [
    ("joybox", 'cd "$JOYBOX_ROOT"'),
    ("jb", 'cd "$JOYBOX_ROOT"'),
    ("jbscripts", 'cd "$JOYBOX_ROOT/Scripts"'),
    ("jbcli", 'cd "$JOYBOX_ROOT/Shared/joybox/cli"'),
    ("jbbootstrap", 'cd "$JOYBOX_ROOT/Bootstrap"'),
    ("jbbackup", "backup_tool"),
    ("jbsync", "sync_tool"),
    ("jblocker", "locker_sync_tool"),
])
def test_each_alias_expands_as_documented(shell, name, expansion):
    result = shell.source(["joybox_aliases.sh"], "alias %s" % name)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "alias %s='%s'\n" % (name, expansion)


def test_the_navigation_aliases_follow_the_repository_root(shell):
    shell.sandbox.write("/srv/joybox/Shared/joybox/cli/.keep", "")
    body = "shopt -s expand_aliases\neval jbcli\npwd"

    result = shell.source(["joybox_aliases.sh"], body, env = {"JOYBOX_ROOT": "/srv/joybox"})

    assert result.stdout == "/srv/joybox/Shared/joybox/cli\n", result.stderr
