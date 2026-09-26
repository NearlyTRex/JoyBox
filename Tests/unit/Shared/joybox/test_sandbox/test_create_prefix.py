# Imports
import pytest

# Local imports
import joybox.command as command
from joybox import commandoptions, sandbox


###########################################################
# Creating a wine prefix
#
# Each command runs as an argv list with no shell, so a trick has to be an
# argument to winetricks, never part of the program name.
###########################################################

TOOLS = {"WineBoot": "/tools/wineboot", "WineTricks": "/tools/winetricks", "WineServer": "/tools/wineserver"}


@pytest.fixture
def ran(monkeypatch, tmp_path):
    commands = []
    monkeypatch.setattr(sandbox.programs, "get_tool_program", lambda name: TOOLS[name])
    monkeypatch.setattr(command, "run_returncode_command",
                        lambda cmd, **kwargs: commands.append(cmd) or 0)
    return commands


def build(tmp_path, tricks):
    options = commandoptions.CommandOptions()
    options.set_is_wine_prefix(True)
    options.set_prefix_dir(str(tmp_path / "prefix"))
    options.set_tricks(tricks)
    return options


def test_tricks_are_arguments_to_winetricks(ran, tmp_path):
    assert sandbox.create_wine_prefix(build(tmp_path, ["d3dx9", "vcrun2019"]))

    assert ["/tools/winetricks", "d3dx9", "vcrun2019"] in ran


def test_no_tricks_runs_only_wineboot(ran, tmp_path):
    assert sandbox.create_wine_prefix(build(tmp_path, []))

    assert ran == [["/tools/wineboot"]]
