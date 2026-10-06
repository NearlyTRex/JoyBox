# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import build_game_metadata_files


###########################################################
# Metadata entries
###########################################################

ROMS = config.Supercategory.ROMS
NINTENDO = config.Category.NINTENDO
SWITCH = config.Subcategory.NINTENDO_SWITCH
WII = config.Subcategory.NINTENDO_WII


@pytest.fixture
def tool(monkeypatch):
    harness = CommandHarness(monkeypatch, build_game_metadata_files)
    harness.built = []
    harness.failing = set()
    names = {SWITCH: ["Alpha", "Beta"], WII: ["Gamma"]}

    def build(game_supercategory, game_category, game_subcategory, game_name, **kwargs):
        harness.built.append(game_name)
        return game_name not in harness.failing

    monkeypatch.setattr(build_game_metadata_files.gameinfo, "iterate_selected_game_categories",
        lambda parser, generation_mode: iter([(ROMS, NINTENDO, SWITCH), (ROMS, NINTENDO, WII)]))
    monkeypatch.setattr(build_game_metadata_files.gameinfo, "find_json_game_names",
        lambda supercategory, category, subcategory: list(names[subcategory]))
    monkeypatch.setattr(build_game_metadata_files.environment, "get_game_metadata_file",
        lambda category, subcategory: "/metadata/%s.txt" % subcategory)
    monkeypatch.setattr(build_game_metadata_files.collection, "build_game_metadata_entry", build)
    return harness


def test_every_game_with_a_json_file_is_built(tool):
    tool.run()

    [(title, details)] = tool.previews
    assert title == "Build game metadata files"
    assert sorted(details) == ["/metadata/Nintendo Switch.txt", "/metadata/Nintendo Wii.txt"]
    assert tool.built == ["Alpha", "Beta", "Gamma"]


def test_a_game_name_selects_only_that_game(tool):
    tool.run("-n", "Beta", "--no-preview")

    assert tool.built == ["Beta"]


def test_a_declined_preview_builds_nothing(tool):
    tool.confirm = False

    tool.run()

    assert tool.built == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_a_failed_entry_stops_the_run(tool):
    tool.failing.add("Alpha")

    assert tool.exit_code("--no-preview") != 0
    assert tool.built == ["Alpha"]
    assert tool.errors == ["Build of metadata file failed!"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, build_game_metadata_files)
