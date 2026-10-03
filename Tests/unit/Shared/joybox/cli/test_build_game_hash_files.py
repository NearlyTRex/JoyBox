# Imports
import os
import runpy
import sys

# Third-party imports
import pytest

# Local imports
from joybox import config, environment, system
from joybox.cli import build_game_hash_files


###########################################################
# Game roots and cleanup
#
# Where each game is hashed from decides which files land in the hash file, and
# a cleanup pass per subcategory keeps the run linear in platforms, not games.
###########################################################

class FakeGameInfo:

    def __init__(self, name, subcategory = config.Subcategory.NINTENDO_SWITCH):
        self.name = name
        self.subcategory = subcategory

    def get_supercategory(self):
        return config.Supercategory.ROMS

    def get_category(self):
        return config.Category.NINTENDO

    def get_subcategory(self):
        return self.subcategory

    def get_name(self):
        return self.name


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    state = {
        "games": [FakeGameInfo("Alpha"), FakeGameInfo("Beta"), FakeGameInfo("Gamma", config.Subcategory.NINTENDO_WII)],
        "selected": [], "built": [], "cleaned": [], "previews": [], "errors": [],
        "build": True, "clean": True, "confirm": True,
    }
    tool_module = build_game_hash_files
    monkeypatch.setattr(tool_module.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(tool_module.logger, "setup_logging", lambda: None)

    def iterate(**kwargs):
        state["selected"].append(kwargs)
        return iter(state["games"])

    def build(**kwargs):
        state["built"].append((kwargs["game_info"].get_name(), kwargs["game_root"], kwargs["locker_type"]))
        return state["build"]

    def clean(**kwargs):
        state["cleaned"].append((kwargs["game_subcategory"], kwargs["locker_root"]))
        return state["clean"]

    def preview(operation, details):
        state["previews"].append(details)
        return state["confirm"]

    monkeypatch.setattr(tool_module.gameinfo, "iterate_selected_game_infos", iterate)
    monkeypatch.setattr(tool_module.collection, "build_hash_files", build)
    monkeypatch.setattr(tool_module.collection, "clean_missing_hash_entries", clean)
    monkeypatch.setattr(tool_module.prompts, "prompt_for_preview", preview)
    monkeypatch.setattr(tool_module.environment, "get_locker_gaming_files_offset",
                        lambda supercategory, category, subcategory, name: os.path.join(subcategory.val(), name))
    monkeypatch.setattr(tool_module.environment, "get_locker_gaming_files_dir",
                        lambda supercategory, category, subcategory, name, locker_type = None:
                        os.path.join("/locker", str(locker_type), subcategory.val(), name))
    log_error = tool_module.logger.log_error

    def record_error(message, **kwargs):
        state["errors"].append(message)
        log_error(message, **kwargs)

    monkeypatch.setattr(tool_module.logger, "log_error", record_error)

    def run(*extra):
        monkeypatch.setattr(sys, "argv", ["build_game_hash_files", *extra])
        return system.run_main(tool_module.main)

    state["run"] = run
    return state


def test_games_are_hashed_from_the_locker_directory(tool):
    tool["run"]("--no-preview", "-l", "Hetzner")

    assert tool["built"] == [
        ("Alpha", "/locker/Hetzner/Nintendo Switch/Alpha", config.LockerType.HETZNER),
        ("Beta", "/locker/Hetzner/Nintendo Switch/Beta", config.LockerType.HETZNER),
        ("Gamma", "/locker/Hetzner/Nintendo Wii/Gamma", config.LockerType.HETZNER),
    ]
    assert tool["selected"][0]["locker_base_dir"] is None
    assert tool["cleaned"] == []


def test_a_base_dir_replaces_the_locker_mount(tool, tmp_path):
    tool["run"]("--no-preview", "-b", str(tmp_path), "-d")

    gaming = os.path.join(str(tmp_path), config.LockerFolderType.GAMING.val())
    assert tool["selected"][0]["locker_base_dir"] == str(tmp_path)
    assert [root for _, root, _ in tool["built"]] == [
        os.path.join(gaming, "Nintendo Switch", "Alpha"),
        os.path.join(gaming, "Nintendo Switch", "Beta"),
        os.path.join(gaming, "Nintendo Wii", "Gamma"),
    ]
    assert tool["cleaned"] == [(config.Subcategory.NINTENDO_SWITCH, gaming), (config.Subcategory.NINTENDO_WII, gaming)]


def test_an_input_path_is_hashed_for_every_game(tool, tmp_path):
    tool["run"]("--no-preview", "-i", str(tmp_path))

    assert [root for _, root, _ in tool["built"]] == [str(tmp_path)] * 3


def test_cleanup_without_a_base_dir_uses_the_locker_gaming_root(tool):
    tool["run"]("--no-preview", "-d")

    gaming = environment.get_locker_gaming_root_dir(None)
    assert tool["cleaned"] == [(config.Subcategory.NINTENDO_SWITCH, gaming), (config.Subcategory.NINTENDO_WII, gaming)]


def test_preview_lists_every_game_root(tool):
    tool["run"]()

    assert tool["previews"] == [[root for _, root, _ in tool["built"]]]
    assert len(tool["built"]) == 3


def test_declined_preview_hashes_nothing(tool):
    tool["confirm"] = False

    tool["run"]("-d")

    assert tool["built"] == []
    assert tool["cleaned"] == []


def test_failed_build_quits(tool):
    tool["build"] = False

    with pytest.raises(SystemExit) as raised:
        tool["run"]("--no-preview", "-d")
    assert raised.value.code != 0
    assert tool["errors"] == ["Build of hash files failed!"]
    assert len(tool["built"]) == 1
    assert tool["cleaned"] == []


def test_failed_cleanup_quits(tool):
    tool["clean"] = False

    with pytest.raises(SystemExit) as raised:
        tool["run"]("--no-preview", "-d")
    assert raised.value.code != 0
    assert tool["errors"] == ["Clean of missing hash entries failed!"]
    assert len(tool["cleaned"]) == 1


def test_run_goes_through_the_shared_error_handling(tool, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["build_game_hash_files", "--no-preview"])

    build_game_hash_files.run()

    assert len(tool["built"]) == 3


def test_running_the_module_starts_the_command(monkeypatch):
    called = []
    monkeypatch.setattr(system, "run_main", lambda main: called.append(main))

    runpy.run_path(build_game_hash_files.__file__, run_name = "__main__")

    assert len(called) == 1
