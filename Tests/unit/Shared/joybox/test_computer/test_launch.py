# Imports
import pytest

# Local imports
from joybox import computer, config


###########################################################
# Launching a computer game
#
# The game prefix is linked to the save directory and the local cache, then
# one of the store's launch programs is picked and run inside it.
###########################################################

class FakeLaunchOptions:

    def __init__(self):
        self.prefix_calls = []
        self.dos_drive = "/prefix/dos_c"
        self.c_drive = "/prefix/drive_c"

    def create_prefix(self, **kwargs):
        self.prefix_calls.append(kwargs)
        return True

    def get_prefix_dos_c_drive(self):
        return self.dos_drive

    def get_prefix_c_drive_real(self):
        return self.c_drive


class FakeProgram:

    def __init__(self):
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(kwargs)
        return "launched"


class FakeLaunchGame:

    def __init__(self, cache_dir):
        self.cache_dir = cache_dir
        self.dos = False
        self.win31 = False
        self.program = FakeProgram()
        self.selected_from = []

    def get_local_cache_dir(self):
        return self.cache_dir

    def get_name(self):
        return "Game"

    def get_platform(self):
        return "Computer - Windows"

    def get_boxfront_asset(self):
        return "/assets/boxfront.png"

    def get_save_dir(self):
        return "/saves/Game"

    def get_general_save_dir(self):
        return "/saves/General"

    def does_store_have_dos_programs(self):
        return self.dos

    def does_store_have_win31_programs(self):
        return self.win31

    def select_store_launch_program(self, base_dir):
        self.selected_from.append(base_dir)
        return self.program


@pytest.fixture
def launch(monkeypatch, tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "Data").mkdir()
    game = FakeLaunchGame(str(cache))
    options = FakeLaunchOptions()
    windows = []
    tokens = []
    monkeypatch.setattr(computer.command, "create_command_options", lambda: options)
    monkeypatch.setattr(computer.platform_info, "is_linux_platform", lambda: True)
    monkeypatch.setattr(computer.platform_info, "is_windows_platform", lambda: False)

    def loading_window(**kwargs):
        windows.append(kwargs)
        kwargs["run_func"]()

    monkeypatch.setattr(computer.gui, "display_loading_window", loading_window)
    monkeypatch.setattr(
        computer.sandbox, "build_token_map",
        lambda **kwargs: tokens.append(kwargs) or {"$TOKEN": "x"})
    return game, options, windows, tokens


def test_a_game_runs_its_selected_program(launch):
    game, options, windows, tokens = launch

    assert computer.launch_computer_game(
        game, capture_type = "video", capture_file = "/out.mp4", fullscreen = True,
        verbose = True) == "launched"
    run = game.program.calls[0]
    assert run["options"] is options
    assert run["token_map"] == {"$TOKEN": "x"}
    assert (run["capture_type"], run["capture_file"], run["fullscreen"]) == \
        ("video", "/out.mp4", True)
    assert run["verbose"] is True
    assert tokens == [{"hdd_base_dir": "/prefix/drive_c"}]


def test_a_game_prefix_links_the_cache_and_saves(launch):
    game, options, windows, tokens = launch
    computer.launch_computer_game(game)
    created = options.prefix_calls[0]

    assert created["prefix_name"] == config.PrefixType.GAME
    assert created["prefix_dir"] == "/saves/Game"
    assert created["general_prefix_dir"] == "/saves/General"
    assert created["linked_prefix"] is True
    assert created["clean_existing"] is False
    assert created["other_links"] == [
        {"from": computer.paths.join_paths(game.cache_dir, "Data"), "to": "Data"}]
    assert (created["is_wine_prefix"], created["is_sandboxie_prefix"]) == (True, False)


def test_the_prefix_is_made_behind_a_loading_window(launch):
    game, options, windows, tokens = launch
    computer.launch_computer_game(game)

    assert windows[0]["image_file"] == "/assets/boxfront.png"
    assert "Game" in windows[0]["message_text"]


@pytest.mark.parametrize("dos,win31,expected", [
    (True, False, "/prefix/dos_c"),
    (False, True, "/prefix/dos_c"),
    (False, False, "/prefix/drive_c"),
])
def test_the_program_is_chosen_from_the_right_drive(launch, dos, win31, expected):
    game, options, windows, tokens = launch
    game.dos = dos
    game.win31 = win31
    computer.launch_computer_game(game)

    assert game.selected_from == [expected]


def test_a_prefix_without_a_drive_cannot_launch(launch):
    game, options, windows, tokens = launch
    options.c_drive = None

    assert computer.launch_computer_game(game) is False
    assert game.selected_from == []


def test_a_game_with_no_program_chosen_cannot_launch(launch):
    # Selection gives nothing back when the install has nothing runnable or the
    # choice is cancelled.
    game, options, windows, tokens = launch
    game.program = None

    assert computer.launch_computer_game(game) is False
