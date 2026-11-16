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
    return next(platform for platform in config.Platform.members() if platforms.is_letter_platform(platform))


def non_letter_platform():
    return next(platform for platform in config.Platform.members() if not platforms.is_letter_platform(platform))


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


@pytest.mark.parametrize("name", ["Alpha", "zulu", "7 Days", "Éclair", "Pokémon Red"])
def test_every_letter_is_one_of_the_expected_folders(name):
    # Names are transliterated to ascii before they reach here, so the folder
    # set stays A-Z plus the numeric one. Anything else is a stray directory.
    expected = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ") | {config.general_folder_numeric}
    letter = gamenaming.derive_game_letter_from_name(paths.replace_invalid_path_characters(name))

    assert letter in expected, f"{name!r} derived {letter!r}"


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
    supercategory, category, _ = gamenaming.derive_game_categories_from_platform(platform)

    assert supercategory == config.Supercategory.ROMS
    assert category is not None, f"{platform} has no category"


def test_a_platform_round_trips_through_its_categories():
    platform = letter_platform()
    _, category, subcategory = gamenaming.derive_game_categories_from_platform(platform)

    assert gamenaming.derive_game_platform_from_categories(category, subcategory) == platform


def test_an_unmatched_subcategory_derives_no_platform():
    class Unmatched:
        def val(self):
            return "No Such Subcategory"

    assert gamenaming.derive_game_platform_from_categories(None, Unmatched()) is None


###########################################################
# Name derivation
#
# A game name carries its region and qualifiers in parentheses; the regular
# name is the clean display form. The pair has to agree, because one derives
# the on-disk path and the other is what gets shown and searched.
###########################################################

@pytest.mark.parametrize("game_name,expected", [
    ("Chrono Trigger (USA)", "Chrono Trigger"),
    ("Final Fantasy VII (USA) (Disc 1)", "Final Fantasy VII"),
    ("Dustforce (USA) (En,Fr,De,Es,It)", "Dustforce"),
])
def test_parenthetical_qualifiers_are_stripped(game_name, expected):
    assert gamenaming.derive_regular_name_from_game_name(game_name) == expected


@pytest.mark.parametrize("game_name,expected", [
    ("Legend of Zelda, The - Ocarina of Time (USA)", "The Legend of Zelda - Ocarina of Time"),
    ("Bug's Life, A (USA)", "A Bug's Life"),
    ("Eye of Judgment, The - Legends (USA)", "The Eye of Judgment - Legends"),
])
def test_a_trailing_article_is_moved_to_the_front(game_name, expected):
    assert gamenaming.derive_regular_name_from_game_name(game_name) == expected


def test_a_name_without_an_article_is_left_alone():
    assert gamenaming.derive_regular_name_from_game_name("Metroid Prime (USA)") == "Metroid Prime"


def test_a_custom_prefix_and_suffix_are_applied():
    derived = gamenaming.derive_regular_name_from_game_name(
        "Chrono Trigger (USA)", custom_prefix = "[", custom_suffix = "]")

    assert derived == "[Chrono Trigger]"


###########################################################
# The inverse
###########################################################

def test_a_region_is_appended():
    assert gamenaming.derive_game_name_from_regular_name("Chrono Trigger") == \
        "Chrono Trigger (USA)"


def test_the_region_is_configurable():
    assert gamenaming.derive_game_name_from_regular_name("Chrono Trigger", "Japan") == \
        "Chrono Trigger (Japan)"


@pytest.mark.parametrize("regular_name,expected", [
    ("The Legend of Zelda - Ocarina of Time", "Legend of Zelda, The - Ocarina of Time (USA)"),
    ("A Bug's Life", "Bug's Life, A (USA)"),
])
def test_a_leading_article_is_moved_to_the_end(regular_name, expected):
    assert gamenaming.derive_game_name_from_regular_name(regular_name) == expected


def test_an_article_moves_behind_the_first_subtitle_segment():
    # "The X - Y" becomes "X, The - Y", not "X - Y, The".
    derived = gamenaming.derive_game_name_from_regular_name("The Eye of Judgment - Legends")

    assert derived == "Eye of Judgment, The - Legends (USA)"


def test_a_colon_becomes_a_dash():
    # Colons are not valid in paths on every platform.
    assert ":" not in gamenaming.derive_game_name_from_regular_name("Game: The Sequel")


def test_an_ampersand_is_spelled_out():
    assert "and" in gamenaming.derive_game_name_from_regular_name("Chip & Dale")


def test_a_ce_suffix_is_expanded():
    assert "Collector's Edition" in \
        gamenaming.derive_game_name_from_regular_name("Some Game CE")


###########################################################
# Round trip
###########################################################

@pytest.mark.parametrize("game_name", [
    "Chrono Trigger (USA)",
    "Legend of Zelda, The - Ocarina of Time (USA)",
    "Bug's Life, A (USA)",
    "Metroid Prime (USA)",
])
def test_a_plain_name_round_trips(game_name):
    regular = gamenaming.derive_regular_name_from_game_name(game_name)

    assert gamenaming.derive_game_name_from_regular_name(regular) == game_name


def test_extra_qualifiers_are_not_restored():
    # Only the region comes back; disc and language qualifiers are dropped on
    # the way to the regular name and stay dropped.
    regular = gamenaming.derive_regular_name_from_game_name("Final Fantasy VII (USA) (Disc 1)")

    assert gamenaming.derive_game_name_from_regular_name(regular) == "Final Fantasy VII (USA)"


###########################################################
# Slugs and search terms
###########################################################

def test_a_slug_comes_from_the_regular_name():
    assert gamenaming.derive_slug_name_from_game_name("Legend of Zelda, The (USA)") == \
        "the_legend_of_zelda"


def test_a_slug_drops_qualifiers():
    assert gamenaming.derive_slug_name_from_game_name("Dustforce (USA) (En,Fr)") == "dustforce"


def test_search_terms_are_url_encoded():
    terms = gamenaming.derive_game_search_terms_from_name("Chrono Trigger (USA)", None)

    assert " " not in terms
    assert "Chrono" in terms
