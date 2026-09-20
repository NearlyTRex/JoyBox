# Imports
import os
import pytest

# Local imports
from joybox import config, environment, gamenaming


###########################################################
# Environment paths
#
# Almost every path in the collection is composed here. A level dropped or
# added puts a game's files somewhere the rest of the code will not look for
# them, and nothing reports an error - the directory is simply empty.
###########################################################

LOCKER = "/locker"
CACHE = "/cache"
METADATA = "/metadata"

CATEGORY = config.Category.NINTENDO
SUBCATEGORY = config.Subcategory.NINTENDO_NES
SUPERCATEGORY = config.Supercategory.ROMS
GAME = "Chrono Trigger (USA)"


@pytest.fixture
def roots(monkeypatch):
    monkeypatch.setattr(environment, "get_locker_root_dir", lambda locker_type = None: LOCKER)
    monkeypatch.setattr(environment, "get_cache_root_dir", lambda: CACHE)
    monkeypatch.setattr(environment, "get_game_metadata_root_dir", lambda: METADATA)
    monkeypatch.setattr(environment, "get_file_metadata_root_dir", lambda: METADATA)
    return LOCKER


def parts(path):
    return path.replace("\\", "/").strip("/").split("/")


def name_path():
    platform = gamenaming.derive_game_platform_from_categories(CATEGORY, SUBCATEGORY)
    return gamenaming.derive_game_name_path_from_name(GAME, platform)


###########################################################
# Roots from settings
#
# The composition tests above replace the roots outright; these cover where
# the roots themselves come from.
###########################################################

LOCKER_ROOT = "/tmp/joybox-test-locker"


@pytest.fixture
def locker(isolated_settings):
    isolated_settings.set_value("UserData.Share", "locker_local_mount_path", LOCKER_ROOT)
    isolated_settings.set_value("UserData.Dirs", "tools_dir", "/tmp/joybox-test-tools")
    isolated_settings.set_value("UserData.Dirs", "emulators_dir", "/tmp/joybox-test-emulators")
    return isolated_settings


def test_the_locker_root_comes_from_settings(locker):
    assert environment.get_locker_root_dir() == LOCKER_ROOT


def test_the_tools_root_comes_from_settings(locker):
    assert environment.get_tools_root_dir() == "/tmp/joybox-test-tools"


def test_the_emulators_root_comes_from_settings(locker):
    assert environment.get_emulators_root_dir() == "/tmp/joybox-test-emulators"


def test_gaming_sits_under_the_locker_root(locker):
    gaming = environment.get_locker_gaming_root_dir()

    assert gaming.startswith(LOCKER_ROOT)
    assert gaming.endswith(str(config.LockerFolderType.GAMING))


def test_development_sits_under_the_locker_root(locker):
    development = environment.get_locker_development_root_dir()

    assert development.startswith(LOCKER_ROOT)
    assert development.endswith(str(config.LockerFolderType.DEVELOPMENT))


def test_archives_sit_under_development(locker):
    assert environment.get_locker_development_archives_root_dir().startswith(
        environment.get_locker_development_root_dir())


@pytest.mark.parametrize("accessor,supercategory", [
    ("get_locker_gaming_roms_root_dir", config.Supercategory.ROMS),
    ("get_locker_gaming_dlc_root_dir", config.Supercategory.DLC),
    ("get_locker_gaming_update_root_dir", config.Supercategory.UPDATES),
    ("get_locker_gaming_tags_root_dir", config.Supercategory.TAGS),
])
def test_each_supercategory_sits_under_gaming(locker, accessor, supercategory):
    derived = getattr(environment, accessor)()

    assert derived.startswith(environment.get_locker_gaming_root_dir())
    assert derived.endswith(str(supercategory))


def test_the_supercategory_directories_are_distinct(locker):
    derived = {
        environment.get_locker_gaming_roms_root_dir(),
        environment.get_locker_gaming_dlc_root_dir(),
        environment.get_locker_gaming_update_root_dir(),
        environment.get_locker_gaming_tags_root_dir(),
    }

    assert len(derived) == 4


def test_derived_paths_are_normalized(locker, isolated_settings):
    # join_paths normalizes, so a trailing separator must not produce a double.
    isolated_settings.set_value("UserData.Share", "locker_local_mount_path", LOCKER_ROOT + "/")

    assert "//" not in environment.get_locker_gaming_roms_root_dir()


def test_changing_the_root_moves_everything(locker, isolated_settings):
    before = environment.get_locker_gaming_roms_root_dir()
    isolated_settings.set_value("UserData.Share", "locker_local_mount_path", "/somewhere/else")
    after = environment.get_locker_gaming_roms_root_dir()

    assert before != after
    assert after.startswith("/somewhere/else")


def test_an_environment_variable_in_the_root_is_expanded(locker, isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_LOCKER", "/expanded/locker")
    isolated_settings.set_value("UserData.Share", "locker_local_mount_path", "$JOYBOX_TEST_LOCKER")

    assert environment.get_locker_root_dir().startswith("/expanded/locker")


def test_the_local_locker_is_the_default(locker):
    assert environment.get_locker_root_dir() == \
        environment.get_locker_root_dir(config.LockerType.LOCAL)

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
# Metadata files
###########################################################

def test_a_json_metadata_dir_carries_its_triple(roots):
    built = parts(environment.get_json_metadata_dir(SUPERCATEGORY, CATEGORY, SUBCATEGORY))

    assert built[-3:] == [str(SUPERCATEGORY), str(CATEGORY), str(SUBCATEGORY)]


def test_a_json_metadata_file_is_named_after_the_game(roots):
    built = environment.get_game_json_metadata_file(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)

    assert os.path.basename(built) == GAME + ".json"


def test_a_json_metadata_file_sits_in_its_letter_folder(roots):
    built = environment.get_game_json_metadata_file(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)
    directory = os.path.dirname(built).replace("\\", "/")

    assert directory.endswith(name_path().replace("\\", "/"))


def test_the_ignore_file_is_shared_by_a_subcategory(roots):
    # One list per console, not one per game.
    built = environment.get_game_json_metadata_ignore_file(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY)

    assert os.path.basename(built) == "ignores.json"
    assert os.path.dirname(built) == environment.get_json_metadata_dir(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY)


def test_two_subcategories_have_separate_ignore_files(roots):
    first = environment.get_game_json_metadata_ignore_file(
        SUPERCATEGORY, CATEGORY, config.Subcategory.NINTENDO_NES)
    second = environment.get_game_json_metadata_ignore_file(
        SUPERCATEGORY, CATEGORY, config.Subcategory.NINTENDO_SNES)

    assert first != second


def test_a_hashes_file_is_one_per_subcategory(roots):
    built = environment.get_game_hashes_metadata_file(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY)

    assert built.endswith(".json")
    assert str(SUBCATEGORY) in built


def test_two_subcategories_have_separate_hash_files(roots):
    first = environment.get_game_hashes_metadata_file(
        SUPERCATEGORY, CATEGORY, config.Subcategory.NINTENDO_NES)
    second = environment.get_game_hashes_metadata_file(
        SUPERCATEGORY, CATEGORY, config.Subcategory.NINTENDO_SNES)

    assert first != second


def test_a_pegasus_metadata_file_is_recognised(roots):
    built = environment.get_game_pegasus_metadata_file(CATEGORY, SUBCATEGORY)

    assert environment.is_game_metadata_file(built) is True


def test_a_json_file_is_not_a_metadata_file(roots):
    assert environment.is_game_metadata_file("/metadata/Json/game.json") is False


###########################################################
# Locker hash files
###########################################################

def test_a_hash_file_groups_by_the_leading_path(roots):
    built = environment.get_file_locker_hashes_file(
        os.sep.join(["Gaming", "Roms", "Nintendo", "Nintendo NES", "game.zip"]))

    assert built.endswith(".csv")
    assert "Nintendo NES" in built


def test_two_paths_in_the_same_group_share_a_hash_file(roots):
    base = ["Gaming", "Roms", "Nintendo", "Nintendo NES"]
    first = environment.get_file_locker_hashes_file(os.sep.join(base + ["a.zip"]))
    second = environment.get_file_locker_hashes_file(os.sep.join(base + ["b.zip"]))

    assert first == second


def test_two_groups_do_not_share_a_hash_file(roots):
    first = environment.get_file_locker_hashes_file(
        os.sep.join(["Gaming", "Roms", "Nintendo", "Nintendo NES", "a.zip"]))
    second = environment.get_file_locker_hashes_file(
        os.sep.join(["Gaming", "Roms", "Nintendo", "Nintendo SNES", "a.zip"]))

    assert first != second


def test_a_shallow_path_groups_by_what_it_has(roots):
    built = environment.get_file_locker_hashes_file(os.sep.join(["Gaming", "a.zip"]))

    assert built.endswith("Gaming.csv")


def test_a_bare_name_falls_back_to_a_root_group(roots):
    # Without this the group key would be empty and every loose file would
    # share an unnamed hash file.
    built = environment.get_file_locker_hashes_file("a.zip")

    assert built.endswith("root.csv")


def test_the_grouping_depth_is_adjustable(roots):
    path = os.sep.join(["Gaming", "Roms", "Nintendo", "Nintendo NES", "a.zip"])
    shallow = environment.get_file_locker_hashes_file(path, depth = 2)
    deep = environment.get_file_locker_hashes_file(path, depth = 4)

    assert shallow != deep


###########################################################
# Cache
###########################################################

def test_the_gaming_cache_sits_under_the_cache(roots):
    assert environment.get_cache_gaming_root_dir().startswith(CACHE)


@pytest.mark.parametrize("accessor,supercategory", [
    ("get_cache_gaming_roms_root_dir", config.Supercategory.ROMS),
    ("get_cache_gaming_installs_root_dir", config.Supercategory.INSTALLS),
    ("get_cache_gaming_saves_root_dir", config.Supercategory.SAVES),
    ("get_cache_gaming_setup_root_dir", config.Supercategory.SETUP),
])
def test_each_cache_area_has_its_own_root(roots, accessor, supercategory):
    assert parts(getattr(environment, accessor)())[-1] == str(supercategory)


def test_the_cache_areas_are_all_distinct(roots):
    built = [environment.get_cache_gaming_rom_dir(CATEGORY, SUBCATEGORY, GAME),
             environment.get_cache_gaming_install_dir(CATEGORY, SUBCATEGORY, GAME),
             environment.get_cache_gaming_save_dir(CATEGORY, SUBCATEGORY, GAME),
             environment.get_cache_gaming_setup_dir(CATEGORY, SUBCATEGORY, GAME)]

    assert len(set(built)) == len(built)


def test_a_cache_save_dir_can_be_split_by_save_type(roots):
    plain = environment.get_cache_gaming_save_dir(CATEGORY, SUBCATEGORY, GAME)
    typed = environment.get_cache_gaming_save_dir(
        CATEGORY, SUBCATEGORY, GAME, save_type = "memcard")

    assert typed.startswith(plain)
    assert typed.endswith("memcard")


def test_a_cache_save_dir_without_a_type_has_no_extra_level(roots):
    built = environment.get_cache_gaming_save_dir(CATEGORY, SUBCATEGORY, GAME)

    assert parts(built)[-1] == GAME
    assert parts(built)[-2] == str(SUBCATEGORY)


def test_the_cache_install_dir_uses_the_derived_name_path(roots):
    built = environment.get_cache_gaming_install_dir(CATEGORY, SUBCATEGORY, GAME)

    assert built.replace("\\", "/").endswith(name_path().replace("\\", "/"))


def test_two_games_do_not_share_a_cache_directory(roots):
    first = environment.get_cache_gaming_rom_dir(
        CATEGORY, SUBCATEGORY, "Chrono Trigger (USA)")
    second = environment.get_cache_gaming_rom_dir(
        CATEGORY, SUBCATEGORY, "Super Metroid (USA)")

    assert first != second


def test_the_cache_and_the_locker_are_separate_trees(roots):
    cache = environment.get_cache_gaming_rom_dir(CATEGORY, SUBCATEGORY, GAME)
    locker = environment.get_locker_gaming_files_dir(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)

    assert not cache.startswith(LOCKER)
    assert not locker.startswith(CACHE)


###########################################################
# Music
###########################################################

GENRE = config.AudioGenreType.members()[0]


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


###########################################################
# Scripts
###########################################################

def test_the_scripts_bin_dir_sits_under_the_scripts_root():
    assert environment.get_scripts_bin_dir().startswith(environment.get_scripts_root_dir())


def test_the_scripts_icons_dir_sits_under_the_scripts_root():
    assert environment.get_scripts_icons_dir().startswith(environment.get_scripts_root_dir())


def test_the_bin_and_icon_directories_are_distinct():
    assert environment.get_scripts_bin_dir() != environment.get_scripts_icons_dir()


@pytest.mark.parametrize("accessor,windows,other", [
    ("get_scripts_command_extension", ".bat", ""),
    ("get_scripts_executable_extension", ".exe", ""),
])
def test_the_script_extensions_follow_the_platform(monkeypatch, accessor, windows, other):
    # Unix has no extension for either, so both are empty there.
    monkeypatch.setattr(environment.platform_info, "is_windows_platform", lambda: True)
    assert getattr(environment, accessor)() == windows

    monkeypatch.setattr(environment.platform_info, "is_windows_platform", lambda: False)
    assert getattr(environment, accessor)() == other


def test_the_windows_script_extensions_are_distinct(monkeypatch):
    monkeypatch.setattr(environment.platform_info, "is_windows_platform", lambda: True)

    assert environment.get_scripts_command_extension() != \
        environment.get_scripts_executable_extension()


###########################################################
# Letter folders
#
# Computer platforms bucket games under a first-letter folder; console
# platforms do not. Which of the two a path uses decides whether the rest of
# the code finds the directory at all.
###########################################################

def letter_categories():
    from joybox import platforms as platform_helpers

    for platform in config.Platform.members():
        if not platform_helpers.is_letter_platform(platform):
            continue
        for subcategory in config.Subcategory.members():
            if platform.val().endswith(subcategory.val()):
                return config.Category.COMPUTER, subcategory, platform
    return None, None, None


LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_PLATFORM = letter_categories()
LETTER_GAME = "Half-Life"

letter_platform = pytest.mark.skipif(
    LETTER_SUBCATEGORY is None, reason = "no letter platform is registered")


@letter_platform
def test_a_letter_platform_buckets_by_first_letter():
    derived = gamenaming.derive_game_name_path_from_name(LETTER_GAME, LETTER_PLATFORM)

    assert derived.replace("\\", "/") == "H/Half-Life"


@letter_platform
def test_a_console_platform_does_not_bucket():
    platform = gamenaming.derive_game_platform_from_categories(CATEGORY, SUBCATEGORY)

    assert gamenaming.derive_game_name_path_from_name(GAME, platform) == GAME


@letter_platform
def test_the_locker_buckets_a_letter_platform_game(roots):
    built = environment.get_locker_gaming_files_dir(
        SUPERCATEGORY, LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_GAME)

    assert parts(built)[-2:] == ["H", LETTER_GAME]


@letter_platform
def test_the_install_cache_buckets_a_letter_platform_game(roots):
    built = environment.get_cache_gaming_install_dir(
        LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_GAME)

    assert parts(built)[-2:] == ["H", LETTER_GAME]


@letter_platform
@pytest.mark.parametrize("accessor", [
    "get_cache_gaming_rom_dir",
    "get_cache_gaming_install_dir",
    "get_cache_gaming_save_dir",
    "get_cache_gaming_setup_dir",
])
def test_every_cache_buckets_a_letter_platform_game(roots, accessor):
    # A game installed somewhere unbucketed would not be found by the code
    # that stored it bucketed.
    built = getattr(environment, accessor)(
        LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_GAME)

    assert parts(built)[-2:] == ["H", LETTER_GAME]


@letter_platform
@pytest.mark.parametrize("accessor", [
    "get_cache_gaming_rom_dir",
    "get_cache_gaming_install_dir",
    "get_cache_gaming_save_dir",
    "get_cache_gaming_setup_dir",
])
def test_every_cache_sits_at_the_same_depth(roots, accessor):
    built = getattr(environment, accessor)(
        LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_GAME)
    locker = environment.get_locker_gaming_files_dir(
        SUPERCATEGORY, LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_GAME)

    assert len(parts(built)) - len(parts(CACHE)) == \
        len(parts(locker)) - len(parts(LOCKER))


@letter_platform
def test_a_typed_save_cache_keeps_its_bucket(roots):
    built = environment.get_cache_gaming_save_dir(
        LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_GAME, save_type = "wine")

    assert parts(built)[-3:] == ["H", LETTER_GAME, "wine"]


@pytest.mark.parametrize("accessor", [
    "get_cache_gaming_rom_dir",
    "get_cache_gaming_install_dir",
    "get_cache_gaming_save_dir",
    "get_cache_gaming_setup_dir",
])
def test_a_console_game_is_never_bucketed(roots, accessor):
    built = getattr(environment, accessor)(CATEGORY, SUBCATEGORY, GAME)

    assert parts(built)[-2:] == [str(SUBCATEGORY), GAME]
