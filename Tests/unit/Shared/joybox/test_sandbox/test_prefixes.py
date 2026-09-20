# Imports
import getpass
import os
import pytest

# Local imports
from joybox import commandoptions, config, sandbox
from sandbox_helpers import options, WINE, SANDBOXIE, NEITHER, PREFIX


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
