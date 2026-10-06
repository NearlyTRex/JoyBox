# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import ps3_rom_tool


###########################################################
# CHD verification
###########################################################

@pytest.fixture
def tool(monkeypatch, tmp_path):
    harness = CommandHarness(monkeypatch, ps3_rom_tool)
    harness.verified = Recorder(result = True)
    monkeypatch.setattr(ps3_rom_tool.playstation, "verify_ps3_chd", harness.verified)
    (tmp_path / "Game.chd").write_bytes(b"x")
    (tmp_path / "Game.dkey").write_bytes(b"x")
    return harness


def test_each_chd_is_verified(tool, tmp_path):
    tool.run("-i", str(tmp_path), "-e")

    assert [call["chd_file"] for call in tool.verified.calls] == [str(tmp_path / "Game.chd")]
    assert tool.previews == [("PS3 ROM tool", ["Path: %s" % tmp_path, "Action: Verify CHD"])]


def test_without_verify_nothing_is_done(tool, tmp_path):
    tool.run("-i", str(tmp_path), "--no-preview")

    assert tool.verified.calls == []
    assert tool.previews == []


def test_a_declined_preview_verifies_nothing(tool, tmp_path):
    tool.confirm = False

    tool.run("-i", str(tmp_path), "-e")

    assert tool.verified.calls == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, ps3_rom_tool)
