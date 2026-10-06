# Imports
import os
import types

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config, environment
from joybox.cli import launch_game_json


###########################################################
# Choosing the game
#
# An explicit JSON file wins over category arguments, which win over random
# selection; anything that cannot be launched ends in an error popup.
###########################################################

PEGASUS_SWITCH = "collection: Nintendo Switch\n\ngame: Alpha\nfile: Alpha.xci\n"


class FakeGameInfo:

    playable = True

    def __init__(self, json_file, **kwargs):
        self.json_file = json_file

    def is_playable(self):
        return FakeGameInfo.playable

    def get_name(self):
        return "Alpha"


def switch_json(name = "Alpha"):
    return environment.get_game_json_metadata_file(
        config.Supercategory.ROMS, config.Category.NINTENDO, config.Subcategory.NINTENDO_SWITCH, name)


def make_file(path, content = "{}"):
    os.makedirs(os.path.dirname(path), exist_ok = True)
    with open(path, "w") as handle:
        handle.write(content)
    return path


@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    harness = CommandHarness(monkeypatch, launch_game_json)
    harness.launched = []
    harness.result = True
    harness.choices = []
    monkeypatch.setattr(FakeGameInfo, "playable", True)
    monkeypatch.setattr(launch_game_json.gameinfo, "GameInfo", FakeGameInfo)

    def launch(**kwargs):
        harness.launched.append(kwargs)
        return harness.result

    def choice(options):
        harness.choices.append(list(options))
        for preferred in (config.Category.NINTENDO, config.Subcategory.NINTENDO_SWITCH):
            if preferred in options:
                return preferred
        return options[0]

    monkeypatch.setattr(launch_game_json.collection, "launch_game", launch)
    monkeypatch.setattr(launch_game_json, "random", types.SimpleNamespace(choice = choice))
    pegasus = make_file(str(tmp_path / "metadata.pegasus.txt"), PEGASUS_SWITCH)
    monkeypatch.setattr(launch_game_json.environment, "get_game_metadata_file", lambda category, subcategory: pegasus)
    return harness


def launched_files(tool):
    return [call["game_info"].json_file for call in tool.launched]


def test_an_input_file_is_launched_with_the_chosen_options(tool, tmp_path):
    json_file = make_file(str(tmp_path / "game.json"))

    tool.run("-i", json_file, "-l", "Gdrive", "-t", "Video", "-f", "-c", "Sony")

    [call] = tool.launched
    assert call["game_info"].json_file == json_file
    assert call["locker_type"] == config.LockerType.GDRIVE
    assert call["capture_type"] == config.CaptureType.VIDEO
    assert call["fullscreen"] is True


def test_category_arguments_find_the_json_file(tool):
    make_file(switch_json())

    tool.run("-c", "Nintendo", "-s", "Nintendo Switch", "-n", "Alpha")

    assert launched_files(tool) == [switch_json()]
    assert tool.launched[0]["locker_type"] == config.LockerType.HETZNER


def test_random_selection_picks_from_launchable_platforms(tool):
    make_file(switch_json())

    tool.run("-r")

    categories, subcategories = tool.choices
    assert categories == config.Category.members()
    assert config.Subcategory.NINTENDO_SWITCH in subcategories
    assert config.Subcategory.NINTENDO_AMIIBO not in subcategories
    assert launched_files(tool) == [switch_json()]


def test_random_selection_keeps_a_given_category_and_subcategory(tool):
    make_file(switch_json())

    tool.run("-r", "-c", "Nintendo", "-s", "Nintendo Switch")

    assert tool.choices == []
    assert launched_files(tool) == [switch_json()]


def test_random_selection_without_an_entry_launches_nothing(tool, monkeypatch):
    monkeypatch.setattr(launch_game_json.metadata.Metadata, "get_random_entry", lambda self: None)

    assert tool.exit_code("-r", "-c", "Nintendo", "-s", "Nintendo Switch") != 0

    assert tool.popups == ["No json file specified"]
    assert tool.launched == []


def test_without_any_selection_nothing_is_launched(tool):
    assert tool.exit_code("-c", "Nintendo") != 0

    assert tool.popups == ["No json file specified"]


def test_a_missing_json_file_is_refused(tool):
    assert tool.exit_code("-c", "Nintendo", "-s", "Nintendo Switch", "-n", "Absent") != 0

    assert tool.popups == ["Json file not found"]
    assert tool.launched == []


def test_an_unplayable_game_is_refused(tool, tmp_path):
    FakeGameInfo.playable = False

    assert tool.exit_code("-i", make_file(str(tmp_path / "game.json"))) != 0

    assert tool.popups == ["Json file not launchable"]
    assert tool.launched == []


def test_a_failed_launch_is_reported(tool, tmp_path):
    tool.result = False

    assert tool.exit_code("-i", make_file(str(tmp_path / "game.json"))) != 0

    assert tool.popups == ["Json file failed to launch"]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, launch_game_json)
