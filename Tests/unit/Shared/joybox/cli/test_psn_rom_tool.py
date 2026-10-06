# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import psn_rom_tool


###########################################################
# Renaming by content id
###########################################################

RENAMERS = {
    "rename_psn_rap_file": "rap_file",
    "rename_psn_package_file": "pkg_file",
    "rename_psn_workbin_file": "workbin_file",
    "rename_psn_fakerif_file": "fakerif_file",
}


@pytest.fixture
def tool(monkeypatch, tmp_path):
    harness = CommandHarness(monkeypatch, psn_rom_tool)
    harness.renamed = []
    for name, key in RENAMERS.items():
        monkeypatch.setattr(psn_rom_tool.playstation, name,
            lambda key = key, **kwargs: harness.renamed.append(kwargs[key].rsplit("/", 1)[-1]))
    for name in ("a.rap", "b.pkg", "c.work.bin", "d.bin", "e.fake.rif", "f.rif"):
        (tmp_path / name).write_bytes(b"x")
    return harness


def test_rename_handles_each_psn_file_kind(tool, tmp_path):
    tool.run("-i", str(tmp_path), "-r", "--no-preview")

    assert tool.renamed == ["a.rap", "b.pkg", "c.work.bin", "e.fake.rif"]


def test_without_rename_nothing_is_touched(tool, tmp_path):
    tool.run("-i", str(tmp_path))

    assert tool.renamed == []
    assert tool.previews == [("PSN ROM tool", ["Path: %s" % tmp_path, "Action: Rename PSN files"])]


def test_a_declined_preview_renames_nothing(tool, tmp_path):
    tool.confirm = False

    tool.run("-i", str(tmp_path), "-r")

    assert tool.renamed == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, psn_rom_tool)
