# Imports
import os

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, FakeGameInfo, assert_entry_points
from joybox import config, environment
from joybox.cli import build_game_hash_files


###########################################################
# Game roots and cleanup
#
# Where each game is hashed from decides which files land in the hash file, and
# a cleanup pass per subcategory keeps the run linear in platforms, not games.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, build_game_hash_files)
    harness.games = [FakeGameInfo("Alpha"), FakeGameInfo("Beta"),
                     FakeGameInfo("Gamma", subcategory = config.Subcategory.NINTENDO_WII)]
    harness.selected = []
    harness.built = []
    harness.cleaned = []
    harness.build = True
    harness.clean = True
    tool_module = build_game_hash_files

    def iterate(**kwargs):
        harness.selected.append(kwargs)
        return iter(harness.games)

    def build(**kwargs):
        harness.built.append((kwargs["game_info"].get_name(), kwargs["game_root"], kwargs["locker_type"]))
        return harness.build

    def clean(**kwargs):
        harness.cleaned.append((kwargs["game_subcategory"], kwargs["locker_root"]))
        return harness.clean

    monkeypatch.setattr(tool_module.gameinfo, "iterate_selected_game_infos", iterate)
    monkeypatch.setattr(tool_module.collection, "build_hash_files", build)
    monkeypatch.setattr(tool_module.collection, "clean_missing_hash_entries", clean)
    monkeypatch.setattr(tool_module.environment, "get_locker_gaming_files_offset",
                        lambda supercategory, category, subcategory, name: os.path.join(subcategory.val(), name))
    monkeypatch.setattr(tool_module.environment, "get_locker_gaming_files_dir",
                        lambda supercategory, category, subcategory, name, locker_type = None:
                        os.path.join("/locker", str(locker_type), subcategory.val(), name))
    return harness


def test_games_are_hashed_from_the_locker_directory(tool):
    tool.run("--no-preview", "-l", "Hetzner")

    assert tool.built == [
        ("Alpha", "/locker/Hetzner/Nintendo Switch/Alpha", config.LockerType.HETZNER),
        ("Beta", "/locker/Hetzner/Nintendo Switch/Beta", config.LockerType.HETZNER),
        ("Gamma", "/locker/Hetzner/Nintendo Wii/Gamma", config.LockerType.HETZNER),
    ]
    assert tool.selected[0]["locker_base_dir"] is None
    assert tool.cleaned == []


def test_a_base_dir_replaces_the_locker_mount(tool, tmp_path):
    tool.run("--no-preview", "-b", str(tmp_path), "-d")

    gaming = os.path.join(str(tmp_path), config.LockerFolderType.GAMING.val())
    assert tool.selected[0]["locker_base_dir"] == str(tmp_path)
    assert [root for _, root, _ in tool.built] == [
        os.path.join(gaming, "Nintendo Switch", "Alpha"),
        os.path.join(gaming, "Nintendo Switch", "Beta"),
        os.path.join(gaming, "Nintendo Wii", "Gamma"),
    ]
    assert tool.cleaned == [(config.Subcategory.NINTENDO_SWITCH, gaming), (config.Subcategory.NINTENDO_WII, gaming)]


def test_an_input_path_is_hashed_for_every_game(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path))

    assert [root for _, root, _ in tool.built] == [str(tmp_path)] * 3


def test_cleanup_without_a_base_dir_uses_the_locker_gaming_root(tool):
    tool.run("--no-preview", "-d")

    gaming = environment.get_locker_gaming_root_dir(None)
    assert tool.cleaned == [(config.Subcategory.NINTENDO_SWITCH, gaming), (config.Subcategory.NINTENDO_WII, gaming)]


def test_preview_lists_every_game_root(tool):
    tool.run()

    assert tool.previews == [("Build game hash files", [root for _, root, _ in tool.built])]
    assert len(tool.built) == 3


def test_declined_preview_hashes_nothing(tool):
    tool.confirm = False

    tool.run("-d")

    assert tool.built == []
    assert tool.cleaned == []


def test_failed_build_quits(tool):
    tool.build = False

    assert tool.exit_code("--no-preview", "-d") != 0
    assert tool.errors == ["Build of hash files failed!"]
    assert len(tool.built) == 1
    assert tool.cleaned == []


def test_failed_cleanup_quits(tool):
    tool.clean = False

    assert tool.exit_code("--no-preview", "-d") != 0
    assert tool.errors == ["Clean of missing hash entries failed!"]
    assert len(tool.cleaned) == 1


def test_run_goes_through_the_shared_error_handling(tool):
    tool.run("--no-preview")

    assert len(tool.built) == 3


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, build_game_hash_files)
