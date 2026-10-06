# Imports
import json
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, gameinfo, metadataentry
from gameinfo_helpers import write_game


class FakeStore:

    def get_key(self):
        return "gog"


@pytest.fixture
def store(monkeypatch):
    monkeypatch.setattr(gameinfo.stores, "get_store_by_platform", lambda platform, **kwargs: FakeStore())


def build(tree, data):
    return gameinfo.GameInfo(json_file = write_game(tree, data))


def program(exe, cwd = ".", **flags):
    return dict({"exe": exe, "cwd": cwd}, **flags)


###########################################################
# Program flags
#
# DOS and Windows 3.1 games launch from the emulated C drive and keep their
# discs; a flag that is never seen sends them down the Windows path.
###########################################################

@pytest.mark.parametrize("flag,check", [
    ("is_dos", "does_store_have_dos_programs"),
    ("is_win31", "does_store_have_win31_programs"),
    ("is_scumm", "does_store_have_scumm_programs"),
])
def test_a_flagged_launch_program_is_found(tree, store, flag, check):
    game = build(tree, {"gog": {"launch": [program("GAME.EXE", **{flag: True})]}})

    assert getattr(game, check)() is True
    assert game.does_store_have_windows_programs() is False


def test_a_flagged_installer_counts_too(tree, store):
    game = build(tree, {"gog": {"setup": {"install": [program("INSTALL.EXE", is_win31 = True)]}}})

    assert game.does_store_have_win31_programs() is True
    assert game.does_store_need_to_keep_discs() is True


def test_a_flag_set_to_false_is_not_a_match(tree, store):
    game = build(tree, {"gog": {"launch": [program("GAME.EXE", is_dos = False)]}})

    assert game.does_store_have_dos_programs() is False
    assert game.does_store_have_windows_programs() is True
    assert game.does_store_need_to_keep_discs() is False


def test_dos_games_keep_their_discs(tree, store):
    game = build(tree, {"gog": {"launch": [program("GAME.EXE", is_dos = True)]}})

    assert game.does_store_need_to_keep_discs() is True


def test_matching_programs_can_name_another_store(tree, store):
    game = build(tree, {"steam": {"launch": [program("GAME.EXE", is_dos = True)]}})

    assert game.does_store_have_dos_programs() is False
    assert game.does_store_have_dos_programs(store_key = "steam") is True


###########################################################
# Setup steps
###########################################################

def test_setup_programs_and_steps_are_wrapped(tree, store):
    game = build(tree, {"gog": {"setup": {
        "install": [program("SETUP.EXE")],
        "preinstall": [{"copy": "a"}],
        "postinstall": [{"copy": "b"}, {"copy": "c"}],
    }}})

    assert [p.get_exe() for p in game.get_store_setup_install_programs()] == ["SETUP.EXE"]
    assert [s.get_data() for s in game.get_store_setup_preinstall_steps()] == [{"copy": "a"}]
    assert len(game.get_store_setup_postinstall_steps()) == 2


def test_a_game_without_setup_has_no_steps(tree, store):
    game = build(tree, {})

    assert game.get_store_setup_install_programs() == []
    assert game.get_store_setup_preinstall_steps() == []
    assert game.get_store_setup_postinstall_steps() == []


###########################################################
# Choosing what to launch
###########################################################

@pytest.fixture
def popups(monkeypatch):
    shown = {"errors": [], "choices": []}
    monkeypatch.setattr(gameinfo.gui, "display_error_popup",
        lambda title_text, message_text: shown["errors"].append(title_text))
    return shown


def choose(monkeypatch, popups, pick):
    def display_choices_window(choice_list, title_text, message_text, button_text, run_func):
        popups["choices"].append(choice_list)
        if pick is not None:
            run_func(pick)
    monkeypatch.setattr(gameinfo.gui, "display_choices_window", display_choices_window)


def test_a_single_recorded_program_is_used(tree, store, popups, tmp_path):
    game = build(tree, {"gog": {"launch": [program("GAME.EXE", "bin")]}})

    chosen = game.select_store_launch_program(str(tmp_path))

    assert (chosen.get_exe(), chosen.get_cwd()) == ("GAME.EXE", "bin")
    assert popups["errors"] == []


def test_the_chosen_program_is_the_one_picked(tree, store, popups, monkeypatch, tmp_path):
    # A root level game.exe must not match a pick of bin/game.exe
    game = build(tree, {"gog": {"launch": [program("game.exe"), program("game.exe", "bin")]}})
    choose(monkeypatch, popups, os.path.join("bin", "game.exe"))

    chosen = game.select_store_launch_program(str(tmp_path))

    assert popups["choices"] == [["game.exe", os.path.join("bin", "game.exe")]]
    assert chosen.get_cwd() == "bin"


def test_closing_the_chooser_launches_nothing(tree, store, popups, monkeypatch, tmp_path):
    game = build(tree, {"gog": {"launch": [program("a.exe"), program("b.exe")]}})
    choose(monkeypatch, popups, None)

    assert game.select_store_launch_program(str(tmp_path)) is None


def test_an_install_with_nothing_runnable_is_reported(tree, store, popups, monkeypatch, tmp_path):
    game = build(tree, {})
    choose(monkeypatch, popups, None)

    assert game.select_store_launch_program(str(tmp_path)) is None
    assert popups["errors"] == ["No runnable files"]
    assert popups["choices"] == []


def test_runnable_files_are_found_and_recorded(tree, store, popups, monkeypatch, tmp_path):
    install = tmp_path / "install"
    for relative in ["Game/game.exe", "Game/readme.txt", "Program Files (x86)/Common Files/helper.exe"]:
        target = install / relative
        target.parent.mkdir(parents = True, exist_ok = True)
        target.write_text("x")
    json_file = write_game(tree, {})
    game = gameinfo.GameInfo(json_file = json_file)

    chosen = game.select_store_launch_program(str(install))

    assert (chosen.get_exe(), chosen.get_cwd()) == ("game.exe", "Game")
    with open(json_file) as handle:
        assert json.load(handle)["gog"]["launch"] == [{"exe": "game.exe", "cwd": "Game"}]


###########################################################
# Files and launch values
###########################################################

def test_files_can_be_filtered_by_extension(tree):
    game = build(tree, {"files": ["Game.CUE", "Game.bin", "Manual.pdf"]})

    assert game.get_files() == ["Game.CUE", "Game.bin", "Manual.pdf"]
    assert game.get_files(".cue") == ["Game.CUE"]
    assert game.get_files([".bin", ".pdf"]) == ["Game.bin", "Manual.pdf"]
    assert build(tree, {}).get_files(".cue") == []


def test_launch_values_are_read(tree):
    data = {
        "launch_name": "name", "launch_file": "file", "launch_dir": "dir",
        "transform_file": "transform", "key_file": "key",
        "dlc": ["dlc"], "update": ["update"], "extra": ["extra"], "dependencies": ["dep"],
    }
    game = build(tree, data)

    assert game.get_launch_name() == "name"
    assert game.get_launch_file() == "file"
    assert game.get_launch_dir() == "dir"
    assert game.get_transform_file() == "transform"
    assert game.get_key_file() == "key"
    assert game.get_dlc() == ["dlc"]
    assert game.get_updates() == ["update"]
    assert game.get_extras() == ["extra"]
    assert game.get_dependencies() == ["dep"]


###########################################################
# Writing the json file
###########################################################

def test_updating_writes_back_only_persistent_keys(tree):
    json_file = write_game(tree, {"launch_name": "old"})
    game = gameinfo.GameInfo(json_file = json_file)
    game.set_value("launch_name", "new")
    game.set_value("files", ["a.bin"])

    assert game.update_json_file() is True

    with open(json_file) as handle:
        written = json.load(handle)
    assert written == {"files": ["a.bin"], "launch_name": "new"}


def test_a_pretend_update_writes_nothing(tree):
    json_file = write_game(tree, {"launch_name": "old"})
    game = gameinfo.GameInfo(json_file = json_file)
    game.set_value("launch_name", "new")

    game.update_json_file(pretend_run = True)

    with open(json_file) as handle:
        assert json.load(handle) == {"launch_name": "old"}


def test_raw_json_round_trips(tree):
    game = build(tree, {"launch_name": "a"})

    assert game.read_raw_json_data() == {"launch_name": "a"}
    game.write_raw_json_data({"launch_name": "b"})
    assert game.read_wrapped_json_data().get_value("launch_name") == "b"


###########################################################
# Metadata
###########################################################

def test_metadata_flags(game):
    entry = metadataentry.MetadataEntry()
    entry.set_value(config.metadata_key_coop, "Yes")
    entry.set_value(config.metadata_key_playable, "No")
    game.set_metadata(entry)

    assert game.is_coop() is True
    assert game.is_playable() is False


def test_written_metadata_lands_in_the_metadata_file(game, monkeypatch):
    written = {}

    class RecordingMetadata:
        def import_from_metadata_file(self, path):
            written["read"] = path
        def set_game(self, platform, name, entry):
            written["game"] = (platform, name, entry)
        def export_to_metadata_file(self, path):
            written["written"] = path

    monkeypatch.setattr(gameinfo.metadata, "Metadata", RecordingMetadata)
    game.write_metadata()
    assert written == {}

    entry = metadataentry.MetadataEntry()
    game.set_metadata(entry)
    game.write_metadata()

    assert written["read"] == written["written"] == game.get_metadata_file()
    assert written["game"] == (game.get_platform(), game.get_name(), entry)


def test_a_pick_outside_the_list_launches_nothing(tree, store, popups, monkeypatch, tmp_path):
    game = build(tree, {"gog": {"launch": [program("a.exe"), program("b.exe")]}})
    choose(monkeypatch, popups, "c.exe")

    assert game.select_store_launch_program(str(tmp_path)) is None
