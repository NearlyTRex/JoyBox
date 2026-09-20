# Imports
import getpass
import pytest

# Local imports
from joybox import commandoptions, config, sandbox


###########################################################
# Prefix paths
#
# Wine and Sandboxie lay out a prefix differently, and every path a game is
# given is resolved through these. A wrong drive or profile path writes a save
# outside the prefix.
###########################################################

PREFIX = "/prefixes/game"


def options(wine = False, sandboxie = False, prefix_dir = PREFIX, prefix_name = None):
    entry = commandoptions.CommandOptions()
    entry.set_is_wine_prefix(wine)
    entry.set_is_sandboxie_prefix(sandboxie)
    if prefix_dir:
        entry.set_prefix_dir(prefix_dir)
    if prefix_name:
        entry.set_prefix_name(prefix_name)
    return entry


WINE = lambda **kwargs: options(wine = True, **kwargs)
SANDBOXIE = lambda **kwargs: options(sandboxie = True, **kwargs)
NEITHER = lambda **kwargs: options(**kwargs)


###########################################################
# Drive paths
###########################################################

def test_the_wine_c_drive_is_drive_c():
    assert sandbox.get_real_drive_path(WINE(), "c") == "/prefixes/game/drive_c"


def test_a_wine_secondary_drive_is_a_dosdevice():
    assert sandbox.get_real_drive_path(WINE(), "d") == "/prefixes/game/dosdevices/d:"


def test_a_wine_drive_letter_is_lowercased():
    # dosdevices entries are lowercase on disk.
    assert sandbox.get_real_drive_path(WINE(), "D") == "/prefixes/game/dosdevices/d:"


def test_an_uppercase_wine_c_drive_is_still_drive_c():
    assert sandbox.get_real_drive_path(WINE(), "C") == "/prefixes/game/drive_c"


def test_a_sandboxie_drive_is_uppercased():
    assert sandbox.get_real_drive_path(SANDBOXIE(), "c") == "/prefixes/game/drive/C"


def test_a_sandboxie_secondary_drive_sits_beside_the_first():
    assert sandbox.get_real_drive_path(SANDBOXIE(), "d") == "/prefixes/game/drive/D"


def test_a_sandboxie_drive_has_no_colon():
    # Sandboxie names the folder after the bare letter.
    assert ":" not in sandbox.get_real_drive_path(SANDBOXIE(), "d")


def test_the_c_drive_shortcut_matches_the_general_lookup():
    for entry in [WINE(), SANDBOXIE()]:
        assert sandbox.get_real_c_drive_path(entry) == sandbox.get_real_drive_path(entry, "c")


def test_a_non_prefix_has_no_drive_path():
    assert sandbox.get_real_drive_path(NEITHER(), "c") is None
    assert sandbox.get_real_c_drive_path(NEITHER()) is None


def test_wine_and_sandboxie_drives_do_not_coincide():
    assert sandbox.get_real_drive_path(WINE(), "d") != sandbox.get_real_drive_path(SANDBOXIE(), "d")


###########################################################
# Profile paths
###########################################################

def test_the_wine_user_profile_is_under_drive_c():
    path = sandbox.get_user_profile_path(WINE())

    assert path.endswith(getpass.getuser())
    assert "drive_c/users" in path.replace("\\", "/")


def test_the_sandboxie_user_profile_is_the_current_user():
    path = sandbox.get_user_profile_path(SANDBOXIE())

    assert path.replace("\\", "/").endswith("user/current")


def test_a_non_prefix_has_no_user_profile():
    assert sandbox.get_user_profile_path(NEITHER()) is None


def test_the_wine_public_profile_is_a_sibling_of_the_user_profile():
    path = sandbox.get_public_profile_path(WINE()).replace("\\", "/")

    assert path.endswith("drive_c/users/Public")


def test_the_sandboxie_public_profile_is_under_the_c_drive():
    path = sandbox.get_public_profile_path(SANDBOXIE()).replace("\\", "/")

    assert path.endswith("drive/C/Public")


def test_a_non_prefix_has_no_public_profile():
    assert sandbox.get_public_profile_path(NEITHER()) is None


def test_the_public_and_user_profiles_are_distinct():
    for entry in [WINE(), SANDBOXIE()]:
        assert sandbox.get_public_profile_path(entry) != sandbox.get_user_profile_path(entry)


###########################################################
# Prefix selection
###########################################################

def test_an_unnamed_prefix_resolves_to_nothing():
    # Without a name there is no directory to pick under the sandbox root.
    assert sandbox.get_prefix(WINE()) is None


def test_a_non_prefix_resolves_to_nothing():
    assert sandbox.get_prefix(NEITHER(prefix_name = "game")) is None


def test_blocking_processes_are_copied_not_shared():
    # The caller's list is reused across launches.
    initial = ["game.exe"]
    sandbox.get_blocking_processes(NEITHER(), initial)

    assert initial == ["game.exe"]


def test_a_non_prefix_blocks_only_what_it_was_given():
    assert sandbox.get_blocking_processes(NEITHER(), ["game.exe"]) == ["game.exe"]


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
