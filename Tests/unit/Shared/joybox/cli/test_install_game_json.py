# Imports
import os

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config, environment
from joybox.cli import install_game_json


###########################################################
# Installing a game
#
# An explicit JSON file wins over category arguments; a failed install or
# addon install ends in an error popup.
###########################################################

class FakeGameInfo:

    def __init__(self, json_file, **kwargs):
        self.json_file = json_file

    def get_name(self):
        return "Alpha"


def make_json(path):
    os.makedirs(os.path.dirname(path), exist_ok = True)
    with open(path, "w") as handle:
        handle.write("{}")
    return path


@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    harness = CommandHarness(monkeypatch, install_game_json)
    harness.installed = []
    harness.addons = []
    harness.result = True
    harness.addon_result = True
    harness.json = make_json(str(tmp_path / "game.json"))
    monkeypatch.setattr(install_game_json.gameinfo, "GameInfo", FakeGameInfo)

    def install(**kwargs):
        harness.installed.append(kwargs)
        return harness.result

    def install_addons(**kwargs):
        harness.addons.append(kwargs)
        return harness.addon_result

    monkeypatch.setattr(install_game_json.collection, "install_game", install)
    monkeypatch.setattr(install_game_json.collection, "install_game_addons", install_addons)
    return harness


def test_an_input_file_is_installed_without_addons(tool):
    tool.run("--no-preview", "-i", tool.json, "-k", "-l", "Gdrive")

    [call] = tool.installed
    assert call["game_info"].json_file == tool.json
    assert call["keep_setup_files"] is True
    assert call["locker_type"] == config.LockerType.GDRIVE
    assert tool.addons == []


def test_category_arguments_find_the_json_file_and_addons_follow(tool):
    json_file = make_json(environment.get_game_json_metadata_file(
        config.Supercategory.ROMS, config.Category.NINTENDO, config.Subcategory.NINTENDO_SWITCH, "Alpha"))

    tool.run("--no-preview", "-c", "Nintendo", "-s", "Nintendo Switch", "-n", "Alpha", "-a")

    assert tool.installed[0]["game_info"].json_file == json_file
    assert len(tool.addons) == 1


def test_without_a_selection_nothing_is_installed(tool):
    assert tool.exit_code("--no-preview", "-c", "Nintendo") != 0

    assert tool.popups == ["No json file specified"]
    assert tool.installed == []


def test_a_missing_json_file_is_refused(tool, tmp_path):
    assert tool.exit_code("--no-preview", "-c", "Nintendo", "-s", "Nintendo Switch", "-n", "Absent") != 0

    assert tool.popups == ["Json file not found"]


def test_a_failed_install_is_reported(tool):
    tool.result = False

    assert tool.exit_code("--no-preview", "-i", tool.json, "-a") != 0

    assert tool.popups == ["Json file failed to install"]
    assert tool.addons == []


def test_a_failed_addon_install_is_reported(tool):
    tool.addon_result = False

    assert tool.exit_code("--no-preview", "-i", tool.json, "-a") != 0

    assert tool.popups == ["Json file addons failed to install"]


def test_the_preview_names_the_game(tool):
    tool.run("-i", tool.json)

    [(title, details)] = tool.previews
    assert title == "Install game"
    assert details == ["JSON file: %s" % tool.json, "Game: Alpha", "Source: Hetzner"]
    assert len(tool.installed) == 1


def test_a_cancelled_preview_installs_nothing(tool):
    tool.confirm = False

    tool.run("-i", tool.json)

    assert tool.installed == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, install_game_json)
