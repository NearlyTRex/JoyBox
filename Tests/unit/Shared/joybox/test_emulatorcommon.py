# Imports
import pytest

# Local imports
from joybox import config
from joybox import command
from joybox import emulatorcommon
from joybox import gui
from joybox import paths


###########################################################
# Simple launch
#
# Every simple emulator launches through these token substitutions, so a token
# left unreplaced hands the emulator a literal GAME_FILE.
###########################################################

CACHE_DIR = "/cache/Game"


class FakeGameInfo:
    def __init__(self, launch_name = "", launch_file = ""):
        self.launch_name = launch_name
        self.launch_file = launch_file

    def get_launch_name(self):
        return self.launch_name

    def get_launch_file(self):
        return self.launch_file

    def get_local_cache_dir(self):
        return CACHE_DIR


@pytest.fixture
def launches(monkeypatch):
    calls = []

    def run_capture_command(**kwargs):
        calls.append(kwargs)
        return 0
    monkeypatch.setattr(command, "run_capture_command", run_capture_command)
    return calls


LAUNCH_CMD = ["emu", config.token_game_file, "--dir", config.token_game_dir, "--name", config.token_game_name]


def test_a_single_launch_file_replaces_every_token(launches):
    info = FakeGameInfo(launch_name = "Acme", launch_file = "acme.iso")

    assert emulatorcommon.simple_launch(info, LAUNCH_CMD, launch_options = "opts", verbose = True) == 0
    assert launches[0]["cmd"] == [
        "emu", paths.join_paths(CACHE_DIR, "acme.iso"), "--dir", CACHE_DIR, "--name", "Acme"]
    assert launches[0]["options"] == "opts"
    assert launches[0]["verbose"] is True


def test_a_one_item_launch_list_is_used_directly(launches):
    info = FakeGameInfo(launch_file = ["only.iso"])

    emulatorcommon.simple_launch(info, LAUNCH_CMD)
    assert launches[0]["cmd"][1] == paths.join_paths(CACHE_DIR, "only.iso")


def test_several_launch_files_ask_the_user_to_choose(launches, monkeypatch):
    shown = {}

    def display_choices_window(**kwargs):
        shown.update(kwargs)
        kwargs["run_func"]("disc2.iso")
    monkeypatch.setattr(gui, "display_choices_window", display_choices_window)
    info = FakeGameInfo(launch_file = ["disc1.iso", "disc2.iso"])

    emulatorcommon.simple_launch(info, LAUNCH_CMD)
    assert shown["choice_list"] == ["disc1.iso", "disc2.iso"]
    assert launches[0]["cmd"][1] == paths.join_paths(CACHE_DIR, "disc2.iso")


def test_nothing_to_run_launches_nothing(launches):
    assert emulatorcommon.simple_launch(FakeGameInfo(), LAUNCH_CMD) is False
    assert launches == []


def test_a_launch_name_alone_leaves_the_file_token(launches):
    info = FakeGameInfo(launch_name = "Acme")

    emulatorcommon.simple_launch(info, LAUNCH_CMD)
    assert launches[0]["cmd"] == ["emu", config.token_game_file, "--dir", CACHE_DIR, "--name", "Acme"]
