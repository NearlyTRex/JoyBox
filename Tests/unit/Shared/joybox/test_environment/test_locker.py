# Imports
import os
import pytest

# Local imports
from joybox import config, environment
from environment_helpers import LOCKER, CATEGORY, SUBCATEGORY, SUPERCATEGORY, GAME, GENRE, parts, name_path


###########################################################
# Locker roots
###########################################################

def test_the_gaming_root_sits_under_the_locker(roots):
    assert environment.get_locker_gaming_root_dir().startswith(LOCKER)


@pytest.mark.parametrize("accessor,supercategory", [
    ("get_locker_gaming_roms_root_dir", config.Supercategory.ROMS),
    ("get_locker_gaming_dlc_root_dir", config.Supercategory.DLC),
    ("get_locker_gaming_update_root_dir", config.Supercategory.UPDATES),
    ("get_locker_gaming_tags_root_dir", config.Supercategory.TAGS),
    ("get_locker_gaming_saves_root_dir", config.Supercategory.SAVES),
    ("get_locker_gaming_assets_root_dir", config.Supercategory.ASSETS),
])
def test_each_supercategory_has_its_own_root(roots, accessor, supercategory):
    assert parts(getattr(environment, accessor)())[-1] == str(supercategory)


def test_the_supercategory_roots_are_all_distinct(roots):
    accessors = ["get_locker_gaming_roms_root_dir", "get_locker_gaming_dlc_root_dir",
                 "get_locker_gaming_update_root_dir", "get_locker_gaming_tags_root_dir",
                 "get_locker_gaming_saves_root_dir", "get_locker_gaming_assets_root_dir",
                 "get_locker_gaming_emulators_root_dir"]
    built = [getattr(environment, name)() for name in accessors]

    assert len(set(built)) == len(built)


def test_the_development_root_sits_under_the_locker(roots):
    assert environment.get_locker_development_root_dir().startswith(LOCKER)


def test_the_development_archive_root_sits_under_development(roots):
    assert environment.get_locker_development_archives_root_dir().startswith(
        environment.get_locker_development_root_dir())


@pytest.mark.parametrize("accessor", [
    "get_locker_gaming_root_dir",
    "get_locker_development_root_dir",
    "get_locker_music_root_dir",
    "get_locker_photos_root_dir",
    "get_locker_programs_root_dir",
])
def test_every_locker_area_is_a_separate_tree(roots, accessor):
    built = getattr(environment, accessor)()

    assert built.startswith(LOCKER)
    assert built != LOCKER


###########################################################
# Game files
###########################################################

def test_a_game_offset_carries_its_whole_triple(roots):
    offset = environment.get_locker_gaming_files_offset(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)

    assert parts(offset)[:3] == [str(SUPERCATEGORY), str(CATEGORY), str(SUBCATEGORY)]


def test_a_game_offset_ends_with_the_derived_name_path(roots):
    # The letter folder comes from the derived path, not the raw name.
    offset = environment.get_locker_gaming_files_offset(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)

    assert offset.replace("\\", "/").endswith(name_path().replace("\\", "/"))


def test_a_game_offset_is_relative(roots):
    # It is joined onto a locker root, so an absolute offset would escape it.
    offset = environment.get_locker_gaming_files_offset(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)

    assert not os.path.isabs(offset)


def test_a_game_files_dir_is_its_offset_under_the_gaming_root(roots):
    built = environment.get_locker_gaming_files_dir(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)
    offset = environment.get_locker_gaming_files_offset(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)

    assert built == os.path.join(environment.get_locker_gaming_root_dir(), offset)


def test_two_supercategories_do_not_share_a_game_directory(roots):
    roms = environment.get_locker_gaming_files_dir(
        config.Supercategory.ROMS, CATEGORY, SUBCATEGORY, GAME)
    dlc = environment.get_locker_gaming_files_dir(
        config.Supercategory.DLC, CATEGORY, SUBCATEGORY, GAME)

    assert roms != dlc


def test_two_games_do_not_share_a_directory(roots):
    first = environment.get_locker_gaming_files_dir(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, "Chrono Trigger (USA)")
    second = environment.get_locker_gaming_files_dir(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, "Super Metroid (USA)")

    assert first != second


###########################################################
# Saves
###########################################################

def test_a_save_dir_sits_under_the_saves_root(roots):
    built = environment.get_locker_gaming_save_dir(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)

    assert built.startswith(environment.get_locker_gaming_saves_root_dir())


def test_a_save_dir_does_not_repeat_the_supercategory(roots):
    # Saves are their own supercategory; the game's own is not part of the path.
    built = environment.get_locker_gaming_save_dir(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)

    assert str(SUPERCATEGORY) not in parts(built)


def test_a_save_dir_uses_the_derived_name_path(roots):
    built = environment.get_locker_gaming_save_dir(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)

    assert built.replace("\\", "/").endswith(name_path().replace("\\", "/"))


def test_two_games_do_not_share_a_save_dir(roots):
    first = environment.get_locker_gaming_save_dir(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, "Chrono Trigger (USA)")
    second = environment.get_locker_gaming_save_dir(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, "Super Metroid (USA)")

    assert first != second


###########################################################
# Assets
###########################################################

ASSET = config.AssetType.members()[0]


def test_an_asset_dir_is_grouped_by_type(roots):
    built = environment.get_locker_gaming_asset_dir(CATEGORY, SUBCATEGORY, ASSET)

    assert parts(built)[-1] == str(ASSET)


def test_an_asset_dir_carries_its_categories(roots):
    built = parts(environment.get_locker_gaming_asset_dir(CATEGORY, SUBCATEGORY, ASSET))

    assert str(CATEGORY) in built
    assert str(SUBCATEGORY) in built


@pytest.mark.parametrize("asset_type", config.AssetType.members())
def test_an_asset_file_takes_the_types_extension(roots, asset_type):
    built = environment.get_locker_gaming_asset_file(
        CATEGORY, SUBCATEGORY, GAME, asset_type)

    assert built.endswith(asset_type.cval())


def test_an_asset_file_is_named_after_the_game(roots):
    built = environment.get_locker_gaming_asset_file(
        CATEGORY, SUBCATEGORY, GAME, ASSET)

    assert os.path.basename(built).startswith(GAME)


def test_an_asset_file_is_flat_not_letter_foldered(roots):
    # Assets are looked up by exact name, so they do not get a letter folder.
    built = environment.get_locker_gaming_asset_file(
        CATEGORY, SUBCATEGORY, GAME, ASSET)

    assert os.path.dirname(built) == environment.get_locker_gaming_asset_dir(
        CATEGORY, SUBCATEGORY, ASSET)


@pytest.mark.parametrize("asset_type", config.AssetType.members())
def test_every_asset_type_lands_in_its_own_directory(roots, asset_type):
    built = environment.get_locker_gaming_asset_file(
        CATEGORY, SUBCATEGORY, GAME, asset_type)

    assert str(asset_type) in parts(built)


def test_two_asset_types_do_not_collide(roots):
    types = config.AssetType.members()
    built = [environment.get_locker_gaming_asset_file(CATEGORY, SUBCATEGORY, GAME, entry)
             for entry in types]

    assert len(set(built)) == len(types)


###########################################################
# Music
###########################################################

def test_an_album_dir_sits_under_its_genre(roots, monkeypatch):
    monkeypatch.setattr(
        environment, "get_locker_music_dir", lambda genre_type = None: "/music/" + str(genre_type))
    built = environment.get_locker_music_album_dir("Some Album", genre_type = GENRE)

    assert parts(built)[-1] == "Some Album"


def test_an_album_dir_nests_under_its_artist(roots):
    with_artist = environment.get_locker_music_album_dir(
        "Some Album", artist_name = "Some Artist", genre_type = GENRE)
    without = environment.get_locker_music_album_dir("Some Album", genre_type = GENRE)

    assert "Some Artist" in parts(with_artist)
    assert with_artist != without


def test_two_albums_do_not_share_a_directory(roots):
    first = environment.get_locker_music_album_dir("First", genre_type = GENRE)
    second = environment.get_locker_music_album_dir("Second", genre_type = GENRE)

    assert first != second


def test_the_music_dir_without_a_genre_is_the_music_root(roots):
    assert environment.get_locker_music_dir() == environment.get_locker_music_root_dir()
    assert parts(environment.get_locker_music_dir())[-1] == str(config.LockerFolderType.MUSIC)


def test_the_music_dir_with_a_genre_nests_under_the_music_root(roots):
    built = environment.get_locker_music_dir(GENRE)

    assert parts(built) == parts(environment.get_locker_music_root_dir()) + [str(GENRE)]


def test_an_album_without_a_genre_sits_directly_under_music(roots):
    built = environment.get_locker_music_album_dir("Some Album", artist_name = "Some Artist")

    assert parts(built)[-3:] == [str(config.LockerFolderType.MUSIC), "Some Artist", "Some Album"]


###########################################################
# Emulators
###########################################################

def test_emulator_binaries_are_split_by_platform(roots):
    built = environment.get_locker_gaming_emulator_binaries_dir("Cemu", "linux")

    assert built.startswith(environment.get_locker_gaming_emulators_root_dir())
    assert parts(built)[-3:] == ["Cemu", "Binaries", "linux"]


def test_emulator_setup_files_sit_beside_the_binaries(roots):
    built = environment.get_locker_gaming_emulator_setup_dir("Cemu")

    assert parts(built)[-2:] == ["Cemu", "Setup"]
    assert parts(built)[:-1] == parts(environment.get_locker_gaming_emulator_binaries_dir("Cemu", "linux"))[:-2]


###########################################################
# Programs
###########################################################

def test_tools_sit_under_programs(roots):
    built = environment.get_locker_programs_tools_root_dir()

    assert parts(built)[-2:] == [str(config.LockerFolderType.PROGRAMS), "Tools"]


def test_a_tool_dir_is_split_by_platform_when_given_one(roots):
    tools = parts(environment.get_locker_programs_tools_root_dir())

    assert parts(environment.get_locker_program_tool_dir("Wine")) == tools + ["Wine"]
    assert parts(environment.get_locker_program_tool_dir("Wine", "linux")) == tools + ["Wine", "linux"]
