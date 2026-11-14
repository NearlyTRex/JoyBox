# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, gameinfo


###########################################################
# Category derivation from a path
#
# The json path encodes the supercategory, category and subcategory, and
# GameInfo asserts all three are non-None during construction - so a path that
# does not parse raises rather than degrading.
###########################################################

METADATA_ROOT = "/metadata"


@pytest.fixture
def metadata_root(isolated_settings):
    isolated_settings.set_value("UserData.Dirs", "game_metadata_dir", METADATA_ROOT)
    return METADATA_ROOT


def json_path(*segments):
    return os.path.join(METADATA_ROOT, "Json", *segments)


@pytest.mark.parametrize("category,subcategory,expected_category", [
    ("Nintendo", "Nintendo 64", config.Category.NINTENDO),
    ("Computer", "Steam", config.Category.COMPUTER),
    ("Sony", "Sony PlayStation 3", config.Category.SONY),
    ("Microsoft", "Microsoft Xbox", config.Category.MICROSOFT),
    ("Other", "Sega Genesis", config.Category.OTHER),
])
def test_a_category_is_derived_from_the_path(metadata_root, category, subcategory, expected_category):
    path = json_path("Roms", category, subcategory, "Game", "Game.json")
    supercategory, derived_category, derived_subcategory = \
        gameinfo.derive_game_categories_from_file(path)

    assert supercategory == config.Supercategory.ROMS
    assert derived_category == expected_category
    assert derived_subcategory is not None


@pytest.mark.parametrize("supercategory", [
    config.Supercategory.ROMS,
    config.Supercategory.DLC,
    config.Supercategory.UPDATES,
])
def test_every_supercategory_is_derived(metadata_root, supercategory):
    path = json_path(supercategory.val(), "Nintendo", "Nintendo 64", "Game", "Game.json")

    assert gameinfo.derive_game_categories_from_file(path)[0] == supercategory


def test_the_subcategory_matches_the_directory(metadata_root):
    path = json_path("Roms", "Nintendo", "Nintendo 64", "Game", "Game.json")

    assert gameinfo.derive_game_categories_from_file(path)[2] == \
        config.Subcategory.NINTENDO_64


def test_an_unrecognised_category_falls_back_to_other(metadata_root):
    path = json_path("Roms", "Sega Genesis", "Sega Genesis", "Game", "Game.json")

    assert gameinfo.derive_game_categories_from_file(path)[1] == config.Category.OTHER


def test_a_path_outside_the_roots_derives_nothing(metadata_root):
    assert gameinfo.derive_game_categories_from_file("/somewhere/else/Game.json") == \
        (None, None, None)


def test_a_path_with_no_supercategory_derives_nothing(metadata_root):
    path = json_path("NotASupercategory", "Nintendo", "Nintendo 64", "Game", "Game.json")

    assert gameinfo.derive_game_categories_from_file(path) == (None, None, None)


def test_a_path_too_shallow_derives_nothing(metadata_root):
    # A supercategory alone cannot identify a game.
    path = json_path("Roms", "Game.json")

    assert gameinfo.derive_game_categories_from_file(path) == (None, None, None)


@pytest.mark.parametrize("candidate", ["", None])
def test_an_invalid_path_derives_nothing(metadata_root, candidate):
    assert gameinfo.derive_game_categories_from_file(candidate) == (None, None, None)


def test_every_platform_directory_layout_parses(metadata_root):
    # Each platform's own category and subcategory must round-trip through the
    # path they are used to build.
    from joybox import gamenaming

    layouts = [
        (platform, gamenaming.derive_game_categories_from_platform(platform))
        for platform in config.Platform.members()]
    layouts = [(platform, parts) for platform, parts in layouts if parts[1] and parts[2]]
    broken = [
        platform for platform, parts in layouts
        if gameinfo.derive_game_categories_from_file(
            json_path(*(part.val() for part in parts), "Game", "Game.json")) != parts]

    assert layouts
    assert not broken, "%s do not round-trip through their path" % broken
