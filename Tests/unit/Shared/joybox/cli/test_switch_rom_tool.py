# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import switch_rom_tool


###########################################################
# Trim and untrim
#
# Each .xci gets a sibling output named for the action; without an action
# nothing is written.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    harness = CommandHarness(monkeypatch, switch_rom_tool)
    harness.trimmed = []
    harness.untrimmed = []
    (tmp_path / "game.xci").write_bytes(b"")
    (tmp_path / "game.nsp").write_bytes(b"")
    nintendo = switch_rom_tool.nintendo
    monkeypatch.setattr(nintendo, "trim_switch_xci", lambda **kwargs: harness.trimmed.append(kwargs))
    monkeypatch.setattr(nintendo, "untrim_switch_xci", lambda **kwargs: harness.untrimmed.append(kwargs))
    return harness


def test_trim_writes_a_trimmed_sibling(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path), "-t", "-d")

    [call] = tool.trimmed
    assert call["src_xci_file"] == str(tmp_path / "game.xci")
    assert call["dest_xci_file"] == str(tmp_path / "game_trimmed.xci")
    assert call["delete_original"] is True
    assert tool.untrimmed == []


def test_untrim_writes_an_untrimmed_sibling(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path), "-u")

    [call] = tool.untrimmed
    assert call["dest_xci_file"] == str(tmp_path / "game_untrimmed.xci")
    assert tool.trimmed == []


@pytest.mark.parametrize("flags, action", [(["-t"], "Trim"), (["-u"], "Untrim"), ([], "None")])
def test_the_preview_names_the_action(tool, tmp_path, flags, action):
    tool.run("-i", str(tmp_path), *flags)

    assert tool.previews[0][1][1] == "Action: %s" % action


def test_without_an_action_nothing_is_written(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path))

    assert tool.trimmed == tool.untrimmed == []


def test_a_cancelled_preview_writes_nothing(tool, tmp_path):
    tool.confirm = False

    tool.run("-i", str(tmp_path), "-t")

    assert tool.trimmed == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, switch_rom_tool)
