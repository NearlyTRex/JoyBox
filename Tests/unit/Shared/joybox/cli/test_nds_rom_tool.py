# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import nds_rom_tool


###########################################################
# nds_rom_tool
#
# Decrypt wins over encrypt; with neither, the ROMs are left alone.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, nds_rom_tool)
    command.decrypt = Recorder(result = True)
    command.encrypt = Recorder(result = True)
    monkeypatch.setattr(nds_rom_tool.nintendo, "decrypt_nds_rom", command.decrypt)
    monkeypatch.setattr(nds_rom_tool.nintendo, "encrypt_nds_rom", command.encrypt)
    return command


@pytest.fixture
def roms(tmp_path):
    for name in ["a.nds", "b.nds", "readme.txt"]:
        (tmp_path / name).write_bytes(b"")
    return tmp_path


def test_decrypt_handles_every_rom(tool, roms):
    tool.main("-i", str(roms), "--no-preview", "-d", "-g")

    assert tool.decrypt.values("nds_file") == [str(roms / "a.nds"), str(roms / "b.nds")]
    assert tool.decrypt.values("generate_hash") == [True, True]
    assert tool.encrypt.calls == []


def test_encrypt_handles_every_rom(tool, roms):
    tool.main("-i", str(roms), "--no-preview", "-e")

    assert tool.encrypt.values("nds_file") == [str(roms / "a.nds"), str(roms / "b.nds")]
    assert tool.decrypt.calls == []


def test_decrypt_wins_when_both_are_given(tool, roms):
    tool.main("-i", str(roms), "-d", "-e")

    assert tool.previews == [("NDS ROM tool", ["Path: %s" % roms, "Action: Decrypt"])]
    assert len(tool.decrypt.calls) == 2
    assert tool.encrypt.calls == []


def test_without_an_action_nothing_is_changed(tool, roms):
    tool.main("-i", str(roms))

    assert tool.previews[0][1][1] == "Action: None"
    assert tool.decrypt.calls == tool.encrypt.calls == []


def test_a_declined_preview_changes_nothing(tool, roms):
    tool.confirm = False

    tool.main("-i", str(roms), "-e")

    assert tool.encrypt.calls == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, nds_rom_tool)
