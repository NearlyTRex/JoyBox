# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import clean_game_json_files


###########################################################
# File selection
#
# Every category is walked; a name whose JSON file is missing is skipped.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    harness = CommandHarness(monkeypatch, clean_game_json_files)
    harness.cleaned = []
    module = clean_game_json_files
    present = tmp_path / "Alpha.json"
    present.write_text("{}")
    harness.present = str(present)

    def find_names(game_supercategory, game_category, game_subcategory):
        if (game_category, game_subcategory) == (config.Category.NINTENDO, config.Subcategory.NINTENDO_SWITCH):
            return ["Alpha", "Missing"]
        return []

    def json_file(game_supercategory, game_category, game_subcategory, game_name):
        if game_supercategory == config.Supercategory.ROMS:
            return str(tmp_path / ("%s.json" % game_name))
        return str(tmp_path / "other" / ("%s.json" % game_name))

    monkeypatch.setattr(module.gameinfo, "find_json_game_names", find_names)
    monkeypatch.setattr(module.environment, "get_game_json_metadata_file", json_file)
    monkeypatch.setattr(module.serialization, "clean_json_file", lambda **kwargs: harness.cleaned.append(kwargs))
    return harness


def test_only_existing_json_files_are_cleaned(tool):
    tool.run("--no-preview")

    assert [call["src"] for call in tool.cleaned] == [tool.present]
    assert tool.cleaned[0]["sort_keys"] and tool.cleaned[0]["remove_empty_values"]


def test_the_preview_lists_the_files(tool):
    tool.run()

    assert tool.previews[0][1] == [tool.present]
    assert len(tool.cleaned) == 1


def test_a_cancelled_preview_cleans_nothing(tool):
    tool.confirm = False

    tool.run()

    assert tool.cleaned == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, clean_game_json_files)
