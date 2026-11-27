# Local imports
from joybox import config
from joybox import prefixlayout


###########################################################
# Token map
#
# Game json paths are written with tokens and expanded per launch, so a token
# that is absent leaves a literal token string in a path.
###########################################################

def build(**kwargs):
    return prefixlayout.build_token_map(**kwargs)


def test_an_empty_token_map_is_built():
    assert build() == {}


def test_the_store_install_dir_is_tokenized():
    assert build(store_install_dir = "/store/game") == \
        {config.TOKEN_STORE_INSTALL_DIR: "/store/game"}


def test_the_game_install_dir_is_tokenized():
    assert build(game_install_dir = "/prefix/drive_c/Game") == \
        {config.TOKEN_GAME_INSTALL_DIR: "/prefix/drive_c/Game"}


def test_the_setup_base_dir_is_tokenized():
    assert build(setup_base_dir = "/setup") == {config.TOKEN_SETUP_MAIN_ROOT: "/setup"}


def test_the_hdd_base_dir_brings_its_computer_folders():
    # DOS and Scumm games address their own roots under the shared hdd.
    token_map = build(hdd_base_dir = "/hdd")

    assert token_map[config.TOKEN_HDD_MAIN_ROOT] == "/hdd"
    assert token_map[config.TOKEN_DOS_MAIN_ROOT].endswith(config.COMPUTER_FOLDER_DOS)
    assert token_map[config.TOKEN_SCUMM_MAIN_ROOT].endswith(config.COMPUTER_FOLDER_SCUMM)


def test_the_dos_and_scumm_roots_sit_under_the_hdd():
    token_map = build(hdd_base_dir = "/hdd")

    assert token_map[config.TOKEN_DOS_MAIN_ROOT].startswith("/hdd")
    assert token_map[config.TOKEN_SCUMM_MAIN_ROOT].startswith("/hdd")


def test_no_hdd_base_dir_leaves_the_computer_roots_out():
    token_map = build(game_install_dir = "/game")

    assert config.TOKEN_DOS_MAIN_ROOT not in token_map
    assert config.TOKEN_SCUMM_MAIN_ROOT not in token_map


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

    assert token_map == {config.TOKEN_DISC_MAIN_ROOT: "/mnt/game"}


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

    assert token_map[config.TOKEN_DISC_MAIN_ROOT] == "/mnt/Game"


def test_no_disc_base_dir_leaves_a_bare_basename():
    token_map = build(disc_files = ["/discs/Game.chd"])

    assert token_map[config.TOKEN_DISC_MAIN_ROOT] == "Game"


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


def test_more_discs_than_drive_letters_map_without_drive_letters():
    discs = ["/discs/Extra %d.chd" % index for index in range(len(config.drives_regular))] + ["/discs/Game.chd"]
    token_map = build(disc_files = discs, disc_base_dir = "/mnt")

    assert token_map[config.TOKEN_DISC_MAIN_ROOT] == "/mnt/Game"


def test_a_disc_past_the_last_drive_letter_falls_back_to_its_path():
    discs = ["/discs/Extra %d.chd" % index for index in range(len(config.drives_regular))] + ["/discs/Game.chd"]
    token_map = build(disc_files = discs, disc_base_dir = "/mnt", use_drive_letters = True)

    assert token_map[config.TOKEN_DISC_MAIN_ROOT] == "/mnt/Game"


def test_a_drive_letter_is_taken_even_by_an_unnumbered_disc():
    token_map = build(
        disc_files = ["/discs/Game.chd", "/discs/Game (Disc 1).chd"],
        use_drive_letters = True)

    assert token_map[config.TOKEN_DISC_MAIN_ROOT] == "d:/"
    assert token_map["DISC_ONE_ROOT"] == "e:/"


def test_discs_and_directories_are_tokenized_together():
    token_map = build(
        game_install_dir = "/game",
        disc_files = ["/discs/Game (Disc 1).chd"],
        disc_base_dir = "/mnt")

    assert token_map[config.TOKEN_GAME_INSTALL_DIR] == "/game"
    assert token_map["DISC_ONE_ROOT"] == "/mnt/Game (Disc 1)"


###########################################################
# Path resolution
###########################################################

def test_a_token_is_replaced():
    token_map = {config.TOKEN_GAME_INSTALL_DIR: "/prefix/drive_c/Game"}

    assert prefixlayout.resolve_path(
        config.TOKEN_GAME_INSTALL_DIR + "/game.exe", token_map) == \
        "/prefix/drive_c/Game/game.exe"


def test_every_token_in_a_path_is_replaced():
    token_map = {
        config.TOKEN_GAME_INSTALL_DIR: "/game",
        config.TOKEN_DISC_MAIN_ROOT: "/mnt/disc",
    }
    resolved = prefixlayout.resolve_path(
        "%s/tool.exe %s" % (config.TOKEN_GAME_INSTALL_DIR, config.TOKEN_DISC_MAIN_ROOT),
        token_map)

    assert resolved == "/game/tool.exe /mnt/disc"


def test_a_repeated_token_is_replaced_everywhere():
    token_map = {config.TOKEN_GAME_INSTALL_DIR: "/game"}
    token = config.TOKEN_GAME_INSTALL_DIR
    resolved = prefixlayout.resolve_path("%s/a %s/b" % (token, token), token_map)

    assert resolved == "/game/a /game/b"


def test_an_unknown_token_is_left_in_place():
    assert prefixlayout.resolve_path("UNKNOWN_TOKEN/game.exe", {}) == "UNKNOWN_TOKEN/game.exe"


def test_a_path_without_tokens_is_unchanged():
    token_map = {config.TOKEN_GAME_INSTALL_DIR: "/game"}

    assert prefixlayout.resolve_path("/absolute/game.exe", token_map) == "/absolute/game.exe"


def test_an_empty_path_stays_empty():
    assert prefixlayout.resolve_path("", {config.TOKEN_GAME_INSTALL_DIR: "/game"}) == ""


def test_a_built_token_map_resolves_its_own_tokens():
    token_map = build(game_install_dir = "/prefix/drive_c/Game", hdd_base_dir = "/hdd")

    resolved = {token: prefixlayout.resolve_path(token, token_map) for token in token_map}

    assert resolved == token_map
