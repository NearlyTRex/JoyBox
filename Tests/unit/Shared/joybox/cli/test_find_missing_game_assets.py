# Imports
import os
from typing import ClassVar

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import find_missing_game_assets


###########################################################
# Missing and extra assets
#
# Every metadata entry should have one file per asset type; files in the
# assets tree that no entry claims are extras.
###########################################################

PLATFORM = "Nintendo Switch"


class FakeEntry:

    def __init__(self, name):
        self.name = name

    def get_game(self):
        return self.name


class FakeMetadata:

    loaded: ClassVar[list] = []
    games: ClassVar[list] = ["Alpha"]

    def import_from_metadata_file(self, metadata_file):
        FakeMetadata.loaded.append(metadata_file)

    def get_sorted_platforms(self):
        return [PLATFORM]

    def get_sorted_entries(self, game_platform):
        return [FakeEntry(name) for name in FakeMetadata.games]


@pytest.fixture
def tool(monkeypatch, tmp_path):
    harness = CommandHarness(monkeypatch, find_missing_game_assets)
    harness.reports = {}
    assets = tmp_path / "assets"
    metadata_dir = tmp_path / "metadata"
    (metadata_dir / PLATFORM).mkdir(parents = True)
    (metadata_dir / PLATFORM / "metadata.pegasus.txt").write_text("")
    (metadata_dir / "notes.txt").write_text("")
    assets.mkdir()
    (assets / "Alpha-BoxFront.jpg").write_text("")
    (assets / "Stray.jpg").write_text("")
    harness.assets = assets
    monkeypatch.setattr(FakeMetadata, "loaded", [])
    monkeypatch.setattr(FakeMetadata, "games", ["Alpha"])
    monkeypatch.setattr(find_missing_game_assets.metadata, "Metadata", FakeMetadata)
    monkeypatch.setattr(find_missing_game_assets.environment, "get_locker_gaming_assets_root_dir", lambda: str(assets))
    monkeypatch.setattr(find_missing_game_assets.environment, "get_game_pegasus_metadata_root_dir", lambda: str(metadata_dir))
    monkeypatch.setattr(find_missing_game_assets.gameinfo, "derive_game_categories_from_platform",
        lambda platform: (config.Supercategory.ROMS, config.Category.NINTENDO, config.Subcategory.NINTENDO_SWITCH))
    monkeypatch.setattr(find_missing_game_assets.environment, "get_locker_gaming_asset_file",
        lambda category, subcategory, name, asset_type: os.path.join(str(assets), "%s-%s%s" % (name, asset_type.val(), asset_type.cval())))

    def report(items, title, max_display, report_file, **kwargs):
        harness.reports[report_file] = (items, max_display)

    monkeypatch.setattr(find_missing_game_assets.reports, "write_list_report", report)
    return harness


def test_missing_and_extra_assets_are_reported_per_type(tool):
    tool.run("--no-preview", "-v")

    assert FakeMetadata.loaded == [str(tool.assets.parent / "metadata" / PLATFORM / "metadata.pegasus.txt")]
    assert tool.reports["Missing_BoxFront.txt"] == ([], 10)
    assert tool.reports["Missing_Label.txt"] == ([str(tool.assets / "Alpha-Label.png")], 10)
    assert tool.reports["Extras.txt"] == ([str(tool.assets / "Stray.jpg")], 10)
    assert len(tool.reports) == len(config.AssetType.members()) + 1


def test_reports_are_written_without_listing_when_quiet(tool):
    tool.run("--no-preview")

    assert {max_display for _, max_display in tool.reports.values()} == {0}


def test_a_confirmed_preview_collects_every_game_missing_a_type(tool, monkeypatch):
    monkeypatch.setattr(FakeMetadata, "games", ["Alpha", "Beta"])

    tool.run()

    assert len(tool.previews) == 1
    assert tool.reports["Missing_Label.txt"][0] == [str(tool.assets / "Alpha-Label.png"), str(tool.assets / "Beta-Label.png")]
    assert tool.reports["Missing_BoxFront.txt"][0] == [str(tool.assets / "Beta-BoxFront.jpg")]


def test_the_preview_names_both_trees_and_a_decline_scans_nothing(tool):
    tool.confirm = False

    tool.run()

    assert tool.previews == [("Find missing game assets", ["Assets dir: %s" % tool.assets,
        "Metadata dir: %s" % (tool.assets.parent / "metadata")])]
    assert tool.reports == {}
    assert tool.warnings == ["Operation cancelled by user"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, find_missing_game_assets)
