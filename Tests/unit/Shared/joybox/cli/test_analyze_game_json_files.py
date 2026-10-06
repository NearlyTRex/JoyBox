# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import analyze_game_json_files


###########################################################
# analyze_game_json_files
#
# Every game JSON in every category is visited; the mode picks which of the
# two findings, no files and unplayable, are listed.
###########################################################

# name -> (files, playable)
GAMES = {
    "Empty": ([], True),
    "Broken": (["broken.sfc"], False),
    "Fine": (["fine.sfc"], True),
    "Unknown": (None, True),
}


class FakeGameInfo:

    def __init__(self, game_name, **kwargs):
        self.name = game_name

    def get_files(self):
        return GAMES[self.name][0]

    def is_playable(self):
        return GAMES[self.name][1]

    def get_json_file(self):
        return self.name + ".json"


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, analyze_game_json_files)
    command.visited = []

    def find_json_game_names(supercategory, category, subcategory):
        command.visited.append((supercategory, category, subcategory))
        if (supercategory, subcategory) == (config.Supercategory.ROMS, config.Subcategory.NINTENDO_SNES):
            return list(GAMES)
        return []

    monkeypatch.setattr(analyze_game_json_files.gameinfo, "find_json_game_names", find_json_game_names)
    monkeypatch.setattr(analyze_game_json_files.gameinfo, "GameInfo", FakeGameInfo)
    return command


def test_every_category_is_visited(tool):
    tool.main()

    expected = sum(len(config.subcategory_map[category]) for category in config.Category.members())
    assert len(tool.visited) == expected * len(config.Supercategory.members())


def test_all_mode_lists_both_findings(tool):
    tool.main()

    assert tool.infos == ["Games with no files:", "Empty.json", "Games marked as unplayable:", "Broken.json"]


def test_missing_files_mode_lists_only_games_without_files(tool):
    tool.main("-m", "MissingGameFiles")

    assert tool.infos == ["Games with no files:", "Empty.json"]


def test_unplayable_mode_lists_only_unplayable_games(tool):
    tool.main("-m", "UnplayableGames")

    assert tool.infos == ["Games marked as unplayable:", "Broken.json"]


def test_nothing_is_listed_when_every_game_is_fine(tool, monkeypatch):
    monkeypatch.setitem(GAMES, "Empty", (["empty.sfc"], True))
    monkeypatch.setitem(GAMES, "Broken", (["broken.sfc"], True))

    tool.main()

    assert tool.infos == []


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, analyze_game_json_files)
