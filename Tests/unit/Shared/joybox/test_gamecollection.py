# Imports
import argparse
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, gamecollection
from gameinfo_helpers import CATEGORY, SUBCATEGORY, write_game

ROMS = config.Supercategory.ROMS
COMPUTER = config.Category.COMPUTER
GOG = config.Subcategory.COMPUTER_GOG


def make_dirs(root, *relatives):
    for relative in relatives:
        os.makedirs(os.path.join(str(root), relative))


###########################################################
# Finding games on disk
###########################################################

def test_game_names_are_listed_in_order(tmp_path):
    base = os.path.join("Roms", CATEGORY.val(), SUBCATEGORY.val())
    make_dirs(tmp_path, os.path.join(base, "Zelda"), os.path.join(base, "Contra"))

    assert gamecollection.find_all_game_names(str(tmp_path), ROMS, CATEGORY, SUBCATEGORY) == ["Contra", "Zelda"]


def test_letter_platforms_list_games_under_their_letters(tmp_path):
    # Computer stores file games under a letter folder
    base = os.path.join("Roms", COMPUTER.val(), GOG.val())
    make_dirs(tmp_path, os.path.join(base, "B", "Beta"), os.path.join(base, "A", "Alpha"), os.path.join(base, "A", "Axe"))

    assert gamecollection.find_all_game_names(str(tmp_path), ROMS, COMPUTER, GOG) == ["Alpha", "Axe", "Beta"]


def test_a_missing_platform_folder_has_no_games(tmp_path):
    assert gamecollection.find_all_game_names(str(tmp_path), ROMS, CATEGORY, SUBCATEGORY) == []


def test_json_and_locker_game_names(game_tree, tmp_path):
    write_game(game_tree, name = "From Json")
    make_dirs(game_tree["locker"], os.path.join("Gaming", "Roms", CATEGORY.val(), SUBCATEGORY.val(), "From Locker"))
    make_dirs(tmp_path, os.path.join("elsewhere", "Gaming", "Roms", CATEGORY.val(), SUBCATEGORY.val(), "From Base"))

    assert gamecollection.find_json_game_names(ROMS, CATEGORY, SUBCATEGORY) == ["From Json"]
    assert gamecollection.find_locker_game_names(ROMS, CATEGORY, SUBCATEGORY, config.LockerType.LOCAL) == ["From Locker"]
    assert gamecollection.find_locker_game_names(
        ROMS, CATEGORY, SUBCATEGORY, locker_base_dir = str(tmp_path / "elsewhere")) == ["From Base"]


def test_json_game_names_can_be_narrowed_to_a_lockers_games(game_tree):
    # Games known only from a store purchase have no files in the locker.
    write_game(game_tree, name = "In Locker")
    write_game(game_tree, name = "Purchase Only")
    make_dirs(game_tree["locker"], os.path.join("Gaming", "Roms", CATEGORY.val(), SUBCATEGORY.val(), "In Locker"))

    assert gamecollection.find_json_game_names(ROMS, CATEGORY, SUBCATEGORY) == ["In Locker", "Purchase Only"]
    assert gamecollection.find_json_game_names(ROMS, CATEGORY, SUBCATEGORY, config.LockerType.LOCAL) == ["In Locker"]


###########################################################
# Iterating the selection
###########################################################

class FakeParser:

    def __init__(self, supercategories = (ROMS,), subcategories = None, **args):
        defaults = {"game_supercategory": ROMS, "game_category": None, "game_subcategory": None, "game_name": None}
        defaults.update(args)
        self.args = argparse.Namespace(**defaults)
        self.supercategories = list(supercategories)
        self.subcategories = subcategories if subcategories is not None else {CATEGORY: [SUBCATEGORY]}

    def parse_known_args(self):
        return self.args, []

    def get_selected_supercategories(self):
        return self.supercategories

    def get_selected_subcategories(self):
        return self.subcategories


CUSTOM = config.GenerationModeType.CUSTOM


def test_standard_mode_walks_every_selected_category():
    parser = FakeParser(
        supercategories = [config.Supercategory.DLC, ROMS],
        subcategories = {COMPUTER: [GOG], CATEGORY: [SUBCATEGORY]})

    triples = list(gamecollection.iterate_selected_game_categories(parser))

    assert len(triples) == 4
    assert triples == sorted(triples)


def test_the_selection_can_be_given_directly():
    triples = list(gamecollection.iterate_selected_game_categories(
        FakeParser(), game_supercategories = [ROMS], game_subcategory_map = {COMPUTER: [GOG]}))

    assert triples == [(ROMS, COMPUTER, GOG)]


def test_custom_mode_uses_the_arguments():
    parser = FakeParser(game_category = CATEGORY, game_subcategory = SUBCATEGORY)

    assert list(gamecollection.iterate_selected_game_categories(parser, CUSTOM)) == [(ROMS, CATEGORY, SUBCATEGORY)]


@pytest.mark.parametrize("args", [
    {},
    {"game_category": CATEGORY},
])
def test_custom_mode_needs_a_category_and_subcategory(args):
    with pytest.raises(ValueError):
        list(gamecollection.iterate_selected_game_categories(FakeParser(**args), CUSTOM))


def test_every_game_in_the_selection_is_built(game_tree):
    write_game(game_tree, name = "Contra")
    write_game(game_tree, name = "Zelda")

    games = list(gamecollection.iterate_selected_game_infos(FakeParser()))

    assert [game.get_name() for game in games] == ["Contra", "Zelda"]


def test_the_selection_can_be_narrowed_to_one_game(game_tree):
    write_game(game_tree, name = "Contra")
    write_game(game_tree, name = "Zelda")

    by_argument = list(gamecollection.iterate_selected_game_infos(FakeParser(game_name = "Zelda")))
    by_filter = list(gamecollection.iterate_selected_game_infos(FakeParser(), game_name_filter = "Contra"))

    assert [game.get_name() for game in by_argument] == ["Zelda"]
    assert [game.get_name() for game in by_filter] == ["Contra"]


def test_games_can_be_found_in_a_locker(game_tree):
    write_game(game_tree, name = "Contra")
    make_dirs(game_tree["locker"], os.path.join("Gaming", "Roms", CATEGORY.val(), SUBCATEGORY.val(), "Contra"))

    games = list(gamecollection.iterate_selected_game_infos(FakeParser(), locker_type = config.LockerType.LOCAL))

    assert [game.get_name() for game in games] == ["Contra"]


def test_a_game_that_cannot_be_built_is_skipped(game_tree):
    write_game(game_tree, name = "Contra")
    make_dirs(game_tree["json"], os.path.join("Roms", CATEGORY.val(), SUBCATEGORY.val(), "No Json"))

    games = list(gamecollection.iterate_selected_game_infos(FakeParser()))

    assert [game.get_name() for game in games] == ["Contra"]


def test_custom_mode_builds_the_named_game(game_tree):
    write_game(game_tree, name = "Contra")
    parser = FakeParser(game_category = CATEGORY, game_subcategory = SUBCATEGORY, game_name = "Contra")

    games = list(gamecollection.iterate_selected_game_infos(parser, CUSTOM))

    assert [game.get_name() for game in games] == ["Contra"]


@pytest.mark.parametrize("args", [
    {},
    {"game_category": CATEGORY},
    {"game_category": CATEGORY, "game_subcategory": SUBCATEGORY},
])
def test_custom_mode_needs_a_whole_game(args):
    with pytest.raises(ValueError):
        list(gamecollection.iterate_selected_game_infos(FakeParser(**args), CUSTOM))


###########################################################
# Best game file
###########################################################

def test_the_lowest_weighted_extension_wins():
    # A playlist beats the individual discs it points at.
    best = gamecollection.find_best_game_file(["/games/game.bin", "/games/game.m3u"])

    assert best.endswith("game.m3u")


def test_a_known_extension_beats_an_unknown_one():
    best = gamecollection.find_best_game_file(["/games/game.unknown", "/games/game.exe"])

    assert best.endswith("game.exe")


@pytest.mark.parametrize("extension", sorted(config.gametype_weights)[:6])
def test_every_weighted_extension_beats_an_unknown_one(extension):
    best = gamecollection.find_best_game_file(["/games/game.unknownext", f"/games/game{extension}"])

    assert best.endswith(extension)


def test_the_result_is_an_absolute_path():
    assert os.path.isabs(gamecollection.find_best_game_file(["relative/game.exe"]))


def test_no_files_yields_nothing():
    assert gamecollection.find_best_game_file([]) == ""


def test_a_non_list_yields_nothing():
    assert gamecollection.find_best_game_file(None) == ""
