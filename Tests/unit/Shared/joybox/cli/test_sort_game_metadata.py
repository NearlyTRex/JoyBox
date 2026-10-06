# Imports
from typing import ClassVar

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import sort_game_metadata


###########################################################
# sort_game_metadata
#
# Every Pegasus metadata file under the root is read and written back in
# order; a pretend run only lists them.
###########################################################

class FakeMetadata:

    log: ClassVar[list] = []

    def import_from_metadata_file(self, metadata_file):
        FakeMetadata.log.append(("import", metadata_file))

    def export_to_metadata_file(self, metadata_file, **kwargs):
        FakeMetadata.log.append(("export", metadata_file, kwargs["append_existing"]))


@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    command = CommandHarness(monkeypatch, sort_game_metadata)
    for name in ["Nintendo/SNES", "Sony/PS1"]:
        (tmp_path / name).mkdir(parents = True)
        (tmp_path / name / "metadata.pegasus.txt").write_text("")
    (tmp_path / "Sony" / "notes.txt").write_text("")
    command.root = tmp_path
    FakeMetadata.log = []
    monkeypatch.setattr(sort_game_metadata.environment, "get_game_pegasus_metadata_root_dir", lambda: str(tmp_path))
    monkeypatch.setattr(sort_game_metadata.metadata, "Metadata", FakeMetadata)
    return command


def test_every_metadata_file_is_rewritten_in_order(tool):
    tool.main("--no-preview")

    snes = str(tool.root / "Nintendo" / "SNES" / "metadata.pegasus.txt")
    ps1 = str(tool.root / "Sony" / "PS1" / "metadata.pegasus.txt")
    assert FakeMetadata.log == [("import", snes), ("export", snes, False), ("import", ps1), ("export", ps1, False)]
    assert "Sort complete: 2 files sorted" in tool.infos


def test_a_pretend_run_rewrites_nothing(tool):
    tool.main("--no-preview", "-p")

    assert FakeMetadata.log == []
    assert "Sort complete: 2 files sorted" in tool.infos


def test_a_confirmed_preview_sorts(tool):
    tool.main()

    assert len(FakeMetadata.log) == 4


def test_the_preview_counts_the_files(tool):
    tool.confirm = False

    tool.main()

    assert tool.previews == [("Sort game metadata", ["Metadata dir: %s" % tool.root, "Files to sort: 2"])]
    assert FakeMetadata.log == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, sort_game_metadata)
