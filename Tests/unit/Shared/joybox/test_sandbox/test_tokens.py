# Imports
import getpass
import os
import pytest

# Local imports
from joybox import commandoptions, config, sandbox
from sandbox_helpers import options, WINE, SANDBOXIE, NEITHER, PREFIX


###########################################################
# Token map
#
# Game json paths are written with tokens and expanded per launch, so a token
# that is absent leaves a literal token string in a path.
###########################################################

def build(**kwargs):
    return sandbox.build_token_map(**kwargs)


def test_an_empty_token_map_is_built():
    assert build() == {}


def test_the_store_install_dir_is_tokenized():
    assert build(store_install_dir = "/store/game") == \
        {config.token_store_install_dir: "/store/game"}


def test_the_game_install_dir_is_tokenized():
    assert build(game_install_dir = "/prefix/drive_c/Game") == \
        {config.token_game_install_dir: "/prefix/drive_c/Game"}


def test_the_setup_base_dir_is_tokenized():
    assert build(setup_base_dir = "/setup") == {config.token_setup_main_root: "/setup"}


def test_the_hdd_base_dir_brings_its_computer_folders():
    # DOS and Scumm games address their own roots under the shared hdd.
    token_map = build(hdd_base_dir = "/hdd")

    assert token_map[config.token_hdd_main_root] == "/hdd"
    assert token_map[config.token_dos_main_root].endswith(config.computer_folder_dos)
    assert token_map[config.token_scumm_main_root].endswith(config.computer_folder_scumm)


def test_the_dos_and_scumm_roots_sit_under_the_hdd():
    token_map = build(hdd_base_dir = "/hdd")

    assert token_map[config.token_dos_main_root].startswith("/hdd")
    assert token_map[config.token_scumm_main_root].startswith("/hdd")


def test_no_hdd_base_dir_leaves_the_computer_roots_out():
    token_map = build(game_install_dir = "/game")

    assert config.token_dos_main_root not in token_map
    assert config.token_scumm_main_root not in token_map


def test_every_path_can_be_tokenized_at_once():
    token_map = build(
        store_install_dir = "/store",
        game_install_dir = "/game",
        setup_base_dir = "/setup",
        hdd_base_dir = "/hdd")

    assert len(token_map) == 6


###########################################################
# Disc tokens
###########################################################

def test_a_single_disc_uses_the_main_disc_token():
    token_map = build(disc_files = ["/discs/game.chd"], disc_base_dir = "/mnt")

    assert token_map == {config.token_disc_main_root: "/mnt/game"}


def test_a_numbered_disc_uses_its_own_token():
    token_map = build(disc_files = ["/discs/Game (Disc 1).chd"], disc_base_dir = "/mnt")

    assert list(token_map) == ["DISC_ONE_ROOT"]


def test_each_numbered_disc_gets_a_distinct_token():
    # Both discs have to stay addressable or disc swapping breaks.
    token_map = build(
        disc_files = ["/discs/Game (Disc 1).chd", "/discs/Game (Disc 2).chd"],
        disc_base_dir = "/mnt")

    assert sorted(token_map) == ["DISC_ONE_ROOT", "DISC_TWO_ROOT"]
    assert token_map["DISC_ONE_ROOT"] == "/mnt/Game (Disc 1)"
    assert token_map["DISC_TWO_ROOT"] == "/mnt/Game (Disc 2)"


def test_an_update_disc_uses_the_update_token():
    token_map = build(disc_files = ["/discs/Game (Update).chd"], disc_base_dir = "/mnt")

    assert list(token_map) == ["DISC_UPDATE_ROOT"]


def test_a_disc_path_is_reduced_to_its_basename():
    token_map = build(disc_files = ["/discs/nested/Game.chd"], disc_base_dir = "/mnt")

    assert token_map[config.token_disc_main_root] == "/mnt/Game"


def test_no_disc_base_dir_leaves_a_bare_basename():
    token_map = build(disc_files = ["/discs/Game.chd"])

    assert token_map[config.token_disc_main_root] == "Game"


def test_drive_letters_replace_paths_when_asked():
    token_map = build(
        disc_files = ["/discs/Game (Disc 1).chd", "/discs/Game (Disc 2).chd"],
        disc_base_dir = "/mnt",
        use_drive_letters = True)

    assert token_map["DISC_ONE_ROOT"] == "d:/"
    assert token_map["DISC_TWO_ROOT"] == "e:/"


def test_drive_letters_are_assigned_in_order():
    discs = ["/discs/Game (Disc %d).chd" % index for index in range(1, 5)]
    token_map = build(disc_files = discs, use_drive_letters = True)

    assert [token_map[key] for key in
            ["DISC_ONE_ROOT", "DISC_TWO_ROOT", "DISC_THREE_ROOT", "DISC_FOUR_ROOT"]] == \
        ["d:/", "e:/", "f:/", "g:/"]


def test_a_drive_letter_is_taken_even_by_an_unnumbered_disc():
    token_map = build(
        disc_files = ["/discs/Game.chd", "/discs/Game (Disc 1).chd"],
        use_drive_letters = True)

    assert token_map[config.token_disc_main_root] == "d:/"
    assert token_map["DISC_ONE_ROOT"] == "e:/"


def test_discs_and_directories_are_tokenized_together():
    token_map = build(
        game_install_dir = "/game",
        disc_files = ["/discs/Game (Disc 1).chd"],
        disc_base_dir = "/mnt")

    assert token_map[config.token_game_install_dir] == "/game"
    assert token_map["DISC_ONE_ROOT"] == "/mnt/Game (Disc 1)"


###########################################################
# Path resolution
###########################################################

def test_a_token_is_replaced():
    token_map = {config.token_game_install_dir: "/prefix/drive_c/Game"}

    assert sandbox.resolve_path(
        config.token_game_install_dir + "/game.exe", token_map) == \
        "/prefix/drive_c/Game/game.exe"


def test_every_token_in_a_path_is_replaced():
    token_map = {
        config.token_game_install_dir: "/game",
        config.token_disc_main_root: "/mnt/disc",
    }
    resolved = sandbox.resolve_path(
        "%s/tool.exe %s" % (config.token_game_install_dir, config.token_disc_main_root),
        token_map)

    assert resolved == "/game/tool.exe /mnt/disc"


def test_a_repeated_token_is_replaced_everywhere():
    token_map = {config.token_game_install_dir: "/game"}
    token = config.token_game_install_dir
    resolved = sandbox.resolve_path("%s/a %s/b" % (token, token), token_map)

    assert resolved == "/game/a /game/b"


def test_an_unknown_token_is_left_in_place():
    assert sandbox.resolve_path("UNKNOWN_TOKEN/game.exe", {}) == "UNKNOWN_TOKEN/game.exe"


def test_a_path_without_tokens_is_unchanged():
    token_map = {config.token_game_install_dir: "/game"}

    assert sandbox.resolve_path("/absolute/game.exe", token_map) == "/absolute/game.exe"


def test_an_empty_path_stays_empty():
    assert sandbox.resolve_path("", {config.token_game_install_dir: "/game"}) == ""


def test_a_built_token_map_resolves_its_own_tokens():
    token_map = build(game_install_dir = "/prefix/drive_c/Game", hdd_base_dir = "/hdd")

    for token, expected in token_map.items():
        assert sandbox.resolve_path(token, token_map) == expected
