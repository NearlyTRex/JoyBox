# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, gameinfo


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
    assert gameinfo.derive_regular_name_from_game_name(game_name) == expected


@pytest.mark.parametrize("game_name,expected", [
    ("Legend of Zelda, The - Ocarina of Time (USA)", "The Legend of Zelda - Ocarina of Time"),
    ("Bug's Life, A (USA)", "A Bug's Life"),
    ("Eye of Judgment, The - Legends (USA)", "The Eye of Judgment - Legends"),
])
def test_a_trailing_article_is_moved_to_the_front(game_name, expected):
    assert gameinfo.derive_regular_name_from_game_name(game_name) == expected


def test_a_name_without_an_article_is_left_alone():
    assert gameinfo.derive_regular_name_from_game_name("Metroid Prime (USA)") == "Metroid Prime"


def test_a_custom_prefix_and_suffix_are_applied():
    derived = gameinfo.derive_regular_name_from_game_name(
        "Chrono Trigger (USA)", custom_prefix = "[", custom_suffix = "]")

    assert derived == "[Chrono Trigger]"


###########################################################
# The inverse
###########################################################

def test_a_region_is_appended():
    assert gameinfo.derive_game_name_from_regular_name("Chrono Trigger") == \
        "Chrono Trigger (USA)"


def test_the_region_is_configurable():
    assert gameinfo.derive_game_name_from_regular_name("Chrono Trigger", "Japan") == \
        "Chrono Trigger (Japan)"


@pytest.mark.parametrize("regular_name,expected", [
    ("The Legend of Zelda - Ocarina of Time", "Legend of Zelda, The - Ocarina of Time (USA)"),
    ("A Bug's Life", "Bug's Life, A (USA)"),
])
def test_a_leading_article_is_moved_to_the_end(regular_name, expected):
    assert gameinfo.derive_game_name_from_regular_name(regular_name) == expected


def test_an_article_moves_behind_the_first_subtitle_segment():
    # "The X - Y" becomes "X, The - Y", not "X - Y, The".
    derived = gameinfo.derive_game_name_from_regular_name("The Eye of Judgment - Legends")

    assert derived == "Eye of Judgment, The - Legends (USA)"


def test_a_colon_becomes_a_dash():
    # Colons are not valid in paths on every platform.
    assert ":" not in gameinfo.derive_game_name_from_regular_name("Game: The Sequel")


def test_an_ampersand_is_spelled_out():
    assert "and" in gameinfo.derive_game_name_from_regular_name("Chip & Dale")


def test_a_ce_suffix_is_expanded():
    assert "Collector's Edition" in \
        gameinfo.derive_game_name_from_regular_name("Some Game CE")


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
    regular = gameinfo.derive_regular_name_from_game_name(game_name)

    assert gameinfo.derive_game_name_from_regular_name(regular) == game_name


def test_extra_qualifiers_are_not_restored():
    # Only the region comes back; disc and language qualifiers are dropped on
    # the way to the regular name and stay dropped.
    regular = gameinfo.derive_regular_name_from_game_name("Final Fantasy VII (USA) (Disc 1)")

    assert gameinfo.derive_game_name_from_regular_name(regular) == "Final Fantasy VII (USA)"


###########################################################
# Slugs and search terms
###########################################################

def test_a_slug_comes_from_the_regular_name():
    assert gameinfo.derive_slug_name_from_game_name("Legend of Zelda, The (USA)") == \
        "the_legend_of_zelda"


def test_a_slug_drops_qualifiers():
    assert gameinfo.derive_slug_name_from_game_name("Dustforce (USA) (En,Fr)") == "dustforce"


def test_search_terms_are_url_encoded():
    terms = gameinfo.derive_game_search_terms_from_name("Chrono Trigger (USA)", None)

    assert " " not in terms
    assert "Chrono" in terms


###########################################################
# Best game file
###########################################################

def test_the_lowest_weighted_extension_wins():
    # A playlist beats the individual discs it points at.
    best = gameinfo.find_best_game_file(["/games/game.bin", "/games/game.m3u"])

    assert best.endswith("game.m3u")


def test_a_known_extension_beats_an_unknown_one():
    best = gameinfo.find_best_game_file(["/games/game.unknown", "/games/game.exe"])

    assert best.endswith("game.exe")


@pytest.mark.parametrize("extension", sorted(config.gametype_weights)[:6])
def test_every_weighted_extension_beats_an_unknown_one(extension):
    best = gameinfo.find_best_game_file(["/games/game.unknownext", f"/games/game{extension}"])

    assert best.endswith(extension)


def test_the_result_is_an_absolute_path():
    assert os.path.isabs(gameinfo.find_best_game_file(["relative/game.exe"]))


def test_no_files_yields_nothing():
    assert gameinfo.find_best_game_file([]) == ""


def test_a_non_list_yields_nothing():
    assert gameinfo.find_best_game_file(None) == ""


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

    for platform in config.Platform.members():
        supercategory, category, subcategory = \
            gamenaming.derive_game_categories_from_platform(platform)
        if not (category and subcategory):
            continue

        path = json_path(supercategory.val(), category.val(), subcategory.val(),
                         "Game", "Game.json")
        derived = gameinfo.derive_game_categories_from_file(path)

        assert derived == (supercategory, category, subcategory), \
            f"{platform} does not round-trip through its path"
