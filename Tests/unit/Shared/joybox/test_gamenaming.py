# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, gamenaming, paths, platforms


###########################################################
# Name derivation
#
# These compose the on-disk layout of the collection, so a change here moves
# every game and asset.
###########################################################

def letter_platform():
    for platform in config.Platform.members():
        if platforms.is_letter_platform(platform):
            return platform
    pytest.skip("no letter platform configured")


def non_letter_platform():
    for platform in config.Platform.members():
        if not platforms.is_letter_platform(platform):
            return platform
    pytest.skip("no non-letter platform configured")


###########################################################
# Letters
###########################################################

@pytest.mark.parametrize("name,expected", [
    ("Chrono Trigger", "C"),
    ("zelda", "Z"),
    ("Metroid", "M"),
])
def test_the_letter_is_the_uppercased_first_character(name, expected):
    assert gamenaming.derive_game_letter_from_name(name) == expected


@pytest.mark.parametrize("name", ["3D Blast", "007 Goldeneye", "1942"])
def test_a_leading_digit_uses_the_numeric_folder(name):
    assert gamenaming.derive_game_letter_from_name(name) == config.general_folder_numeric


def test_an_empty_name_has_no_letter():
    assert gamenaming.derive_game_letter_from_name("") == ""


def test_every_letter_is_one_of_the_expected_folders():
    # Names are transliterated to ascii before they reach here, so the folder
    # set stays A-Z plus the numeric one. Anything else is a stray directory.
    expected = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    for name in ["Alpha", "zulu", "7 Days", "Éclair", "Pokémon Red"]:
        cleaned = paths.replace_invalid_path_characters(name)
        letter = gamenaming.derive_game_letter_from_name(cleaned)
        assert letter in expected or letter == config.general_folder_numeric, \
            f"{name!r} derived {letter!r}"


###########################################################
# Name paths
###########################################################

def test_a_letter_platform_nests_under_the_letter():
    derived = gamenaming.derive_game_name_path_from_name("Chrono Trigger", letter_platform())

    assert derived == os.path.join("C", "Chrono Trigger")


def test_a_non_letter_platform_uses_the_name_alone():
    derived = gamenaming.derive_game_name_path_from_name("Chrono Trigger", non_letter_platform())

    assert derived == "Chrono Trigger"


def test_a_numeric_name_nests_under_the_numeric_folder():
    derived = gamenaming.derive_game_name_path_from_name("1942", letter_platform())

    assert derived.startswith(config.general_folder_numeric)


###########################################################
# Asset paths
###########################################################

@pytest.mark.parametrize("asset_type", config.AssetType.members())
def test_an_asset_path_is_the_type_then_the_name(asset_type):
    derived = gamenaming.derive_game_asset_path_from_name("Chrono Trigger", asset_type)

    assert derived.startswith(asset_type.val() + "/")
    assert "Chrono Trigger" in derived


@pytest.mark.parametrize("asset_type", config.AssetType.members())
def test_an_asset_path_carries_the_type_extension(asset_type):
    derived = gamenaming.derive_game_asset_path_from_name("Chrono Trigger", asset_type)

    assert derived.endswith(asset_type.cval())


def test_asset_paths_differ_per_type():
    derived = {
        gamenaming.derive_game_asset_path_from_name("Game", asset_type)
        for asset_type in config.AssetType.members()
    }

    assert len(derived) == len(config.AssetType.members())


###########################################################
# Categories
###########################################################

def test_categories_are_derived_from_a_platform():
    supercategory, category, subcategory = \
        gamenaming.derive_game_categories_from_platform(letter_platform())

    assert supercategory == config.Supercategory.ROMS
    assert category is not None
    assert subcategory is not None


def test_no_platform_derives_nothing():
    assert gamenaming.derive_game_categories_from_platform(None) == (None, None, None)


@pytest.mark.parametrize("platform", config.Platform.members())
def test_every_platform_derives_a_category(platform):
    # A platform with no category would land its games outside the tree.
    supercategory, category, subcategory = \
        gamenaming.derive_game_categories_from_platform(platform)

    assert supercategory == config.Supercategory.ROMS
    assert category is not None, f"{platform} has no category"


def test_a_platform_round_trips_through_its_categories():
    platform = letter_platform()
    _, category, subcategory = gamenaming.derive_game_categories_from_platform(platform)

    assert gamenaming.derive_game_platform_from_categories(category, subcategory) == platform
