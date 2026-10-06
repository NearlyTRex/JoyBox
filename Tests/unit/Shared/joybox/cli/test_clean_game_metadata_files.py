# Imports
from typing import ClassVar

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import clean_game_metadata_files


###########################################################
# Sorting existing metadata files
###########################################################

class FakeMetadata:

    log: ClassVar[list] = []

    def import_from_metadata_file(self, metadata_file):
        FakeMetadata.log.append(("import", metadata_file))

    def export_to_metadata_file(self, metadata_file):
        FakeMetadata.log.append(("export", metadata_file))


@pytest.fixture
def tool(monkeypatch, tmp_path):
    harness = CommandHarness(monkeypatch, clean_game_metadata_files)
    monkeypatch.setattr(FakeMetadata, "log", [])
    monkeypatch.setattr(clean_game_metadata_files.metadata, "Metadata", FakeMetadata)
    switch = tmp_path / "switch.txt"
    switch.write_text("")
    harness.switch = str(switch)

    def metadata_file(game_category, game_subcategory):
        if game_subcategory == config.Subcategory.NINTENDO_SWITCH:
            return harness.switch
        return str(tmp_path / "absent.txt")

    monkeypatch.setattr(clean_game_metadata_files.environment, "get_game_metadata_file", metadata_file)
    return harness


def test_only_existing_metadata_files_are_rewritten(tool):
    tool.run()

    assert tool.previews == [("Clean game metadata files (sort entries)", [tool.switch])]
    assert FakeMetadata.log == [("import", tool.switch), ("export", tool.switch)]


def test_no_preview_rewrites_without_asking(tool):
    tool.run("--no-preview")

    assert tool.previews == []
    assert FakeMetadata.log == [("import", tool.switch), ("export", tool.switch)]


def test_a_declined_preview_rewrites_nothing(tool):
    tool.confirm = False

    tool.run()

    assert FakeMetadata.log == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, clean_game_metadata_files)
