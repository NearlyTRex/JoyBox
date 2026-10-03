# Imports
import os
import pytest

# Local imports
from joybox import config, environment
from environment_helpers import CATEGORY, SUBCATEGORY, SUPERCATEGORY, GAME, GENRE, METADATA, parts, name_path


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


def test_a_file_exactly_depth_deep_groups_by_its_folder(roots):
    # The file name never counts toward the depth, so loose files share
    # their folder's hash file instead of each getting one.
    built = environment.get_file_locker_hashes_file(os.sep.join(["Photos", "b.jpg"]), depth = 2)

    assert built.endswith("Photos.csv")


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
# Metadata roots
###########################################################

@pytest.mark.parametrize("accessor,leaf", [
    ("get_game_pegasus_metadata_root_dir", "Pegasus"),
    ("get_game_published_metadata_root_dir", "Published"),
    ("get_game_misc_metadata_root_dir", "Misc"),
    ("get_game_hashes_metadata_root_dir", "Hashes"),
    ("get_game_json_metadata_root_dir", "Json"),
])
def test_each_game_metadata_area_sits_under_the_metadata_root(roots, accessor, leaf):
    assert parts(getattr(environment, accessor)()) == parts(METADATA) + [leaf]


def test_a_pegasus_asset_dir_sits_beside_its_metadata_file(roots):
    asset_type = config.AssetType.members()[0]
    asset_dir = environment.get_game_pegasus_metadata_asset_dir(CATEGORY, SUBCATEGORY, asset_type)
    metadata_file = environment.get_game_pegasus_metadata_file(CATEGORY, SUBCATEGORY)

    assert parts(asset_dir)[:-1] == parts(metadata_file)[:-1]
    assert parts(asset_dir)[-1] == str(asset_type)


def test_the_pegasus_format_maps_to_the_pegasus_file(roots):
    assert environment.get_game_metadata_file(CATEGORY, SUBCATEGORY) == \
        environment.get_game_pegasus_metadata_file(CATEGORY, SUBCATEGORY)


def test_an_unknown_metadata_format_has_no_file(roots):
    assert environment.get_game_metadata_file(CATEGORY, SUBCATEGORY, metadata_format = "Unknown") is None


###########################################################
# Audio metadata
###########################################################

TAG = config.AudioMetadataType.TAG


def test_audio_metadata_is_split_by_type_and_genre(roots):
    built = environment.get_file_audio_metadata_root_dir(TAG, GENRE)

    assert parts(built) == parts(METADATA) + ["Audio", str(TAG), str(GENRE)]


def test_audio_metadata_nests_under_an_artist_when_given_one(roots):
    plain = environment.get_file_audio_metadata_dir(TAG, GENRE)
    nested = environment.get_file_audio_metadata_dir(TAG, GENRE, artist_name = "Some Artist")

    assert plain == environment.get_file_audio_metadata_root_dir(TAG, GENRE)
    assert parts(nested) == parts(plain) + ["Some Artist"]


def test_an_archive_file_is_one_text_file_per_album(roots):
    built = environment.get_file_audio_metadata_archive_file(GENRE, "Some Album")

    assert parts(built) == parts(METADATA) + ["Audio", str(config.AudioMetadataType.ARCHIVE), str(GENRE), "Some Album.txt"]


@pytest.mark.parametrize("artist_name", [None, "Some Artist"])
def test_an_album_dir_and_file_share_a_parent(roots, artist_name):
    album_dir = environment.get_file_audio_metadata_album_dir(TAG, GENRE, "Some Album", artist_name)
    album_file = environment.get_file_audio_metadata_file(TAG, GENRE, "Some Album", artist_name)
    parent = environment.get_file_audio_metadata_dir(TAG, GENRE, artist_name)

    assert parts(album_dir) == parts(parent) + ["Some Album"]
    assert parts(album_file) == parts(parent) + ["Some Album.json"]


def test_an_album_without_a_genre_sits_at_the_metadata_root(roots):
    assert parts(environment.get_file_audio_metadata_album_dir(TAG, None, "Some Album")) == \
        parts(METADATA) + ["Some Album"]
    assert parts(environment.get_file_audio_metadata_file(TAG, None, "Some Album")) == \
        parts(METADATA) + ["Some Album.json"]
