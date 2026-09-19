# Imports
import pytest

# Local imports
from joybox import backup, config


###########################################################
# Path resolution
#
# Decides where a backup lands. A wrong answer here writes a game's archive
# into another game's folder, or into the locker root.
###########################################################

ROOT = "/locker/root"


@pytest.fixture
def locker_root(monkeypatch):
    monkeypatch.setattr(backup.environment, "get_locker_root_dir", lambda locker_type = None: ROOT)
    return ROOT


def gaming(*parts):
    return "/".join([ROOT, str(config.LockerFolderType.GAMING)] + list(parts))


###########################################################
# Existing paths
###########################################################

def test_an_existing_path_is_used_as_is(tmp_path, locker_root):
    assert backup.resolve_path(path = str(tmp_path)) == str(tmp_path)


def test_an_existing_path_wins_over_categories(tmp_path, locker_root):
    resolved = backup.resolve_path(
        path = str(tmp_path),
        game_supercategory = "Games",
        game_category = "Microsoft",
        game_subcategory = "Windows")

    assert resolved == str(tmp_path)


def test_a_base_path_overrides_an_existing_path(tmp_path, locker_root):
    # The override exists so a caller can redirect a backup that already has a
    # resolved location.
    other = tmp_path / "other"
    other.mkdir()

    assert backup.resolve_path(path = str(tmp_path), base_path = str(other)) == str(other)


def test_a_missing_path_falls_back_to_the_locker_root(tmp_path, locker_root):
    assert backup.resolve_path(path = str(tmp_path / "absent")) == ROOT


def test_no_path_falls_back_to_the_locker_root(locker_root):
    assert backup.resolve_path() == ROOT


def test_a_missing_base_path_falls_back_to_the_locker_root(tmp_path, locker_root):
    resolved = backup.resolve_path(base_path = str(tmp_path / "absent"))

    assert resolved == ROOT


###########################################################
# Category layout
###########################################################

def test_a_supercategory_sits_under_gaming(locker_root):
    assert backup.resolve_path(game_supercategory = "Games") == gaming("Games")


def test_a_full_triple_builds_the_whole_path(locker_root):
    resolved = backup.resolve_path(
        game_supercategory = "Games",
        game_category = "Microsoft",
        game_subcategory = "Windows")

    assert resolved == gaming("Games", "Microsoft", "Windows")


def test_an_offset_is_appended_last(locker_root):
    resolved = backup.resolve_path(
        game_supercategory = "Games",
        game_category = "Microsoft",
        game_subcategory = "Windows",
        game_offset = "Half-Life")

    assert resolved == gaming("Games", "Microsoft", "Windows", "Half-Life")


def test_categories_build_on_a_base_path(tmp_path, locker_root):
    resolved = backup.resolve_path(
        base_path = str(tmp_path),
        game_supercategory = "Games",
        game_category = "Microsoft")

    assert resolved == "/".join([
        str(tmp_path), str(config.LockerFolderType.GAMING), "Games", "Microsoft"])


###########################################################
# Partial categories
#
# The triple is nested, so a gap stops the walk rather than skipping a level -
# otherwise a game with no category would land beside one that has one.
###########################################################

def test_a_category_without_a_supercategory_is_ignored(locker_root):
    assert backup.resolve_path(game_category = "Microsoft") == ROOT


def test_a_subcategory_without_a_category_is_ignored(locker_root):
    resolved = backup.resolve_path(
        game_supercategory = "Games", game_subcategory = "Windows")

    assert resolved == gaming("Games")


def test_an_offset_without_a_subcategory_is_ignored(locker_root):
    resolved = backup.resolve_path(
        game_supercategory = "Games",
        game_category = "Microsoft",
        game_offset = "Half-Life")

    assert resolved == gaming("Games", "Microsoft")


def test_an_offset_alone_is_ignored(locker_root):
    assert backup.resolve_path(game_offset = "Half-Life") == ROOT


@pytest.mark.parametrize("empty", ["", None])
def test_an_empty_supercategory_stops_the_walk(locker_root, empty):
    resolved = backup.resolve_path(
        game_supercategory = empty,
        game_category = "Microsoft",
        game_subcategory = "Windows")

    assert resolved == ROOT


@pytest.mark.parametrize("empty", ["", None])
def test_an_empty_category_stops_the_walk(locker_root, empty):
    resolved = backup.resolve_path(
        game_supercategory = "Games",
        game_category = empty,
        game_subcategory = "Windows")

    assert resolved == gaming("Games")


###########################################################
# Locker selection
###########################################################

def test_the_requested_locker_is_used(monkeypatch):
    seen = []

    def root(locker_type = None):
        seen.append(locker_type)
        return "/hetzner/root"

    monkeypatch.setattr(backup.environment, "get_locker_root_dir", root)
    resolved = backup.resolve_path(
        locker_type = config.LockerType.HETZNER, game_supercategory = "Games")

    assert seen == [config.LockerType.HETZNER]
    assert resolved.startswith("/hetzner/root")


def test_a_base_path_skips_the_locker_lookup(tmp_path, monkeypatch):
    # An explicit base path should not need a mounted locker.
    def root(locker_type = None):
        raise AssertionError("locker root should not be consulted")

    monkeypatch.setattr(backup.environment, "get_locker_root_dir", root)

    assert backup.resolve_path(base_path = str(tmp_path)) == str(tmp_path)
