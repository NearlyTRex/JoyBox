# Imports
import getpass

# Third-party imports
import pytest

# Local imports
from joybox import prefixlayout
from sandbox_helpers import WINE, SANDBOXIE, NEITHER


###########################################################
# Prefix paths
#
# Wine and Sandboxie lay out a prefix differently, and every path a game is
# given is resolved through these. A wrong drive or profile path writes a save
# outside the prefix.
###########################################################

###########################################################
# Drive paths
###########################################################

def test_the_wine_c_drive_is_drive_c():
    assert prefixlayout.get_real_drive_path(WINE(), "c") == "/prefixes/game/drive_c"


def test_a_wine_secondary_drive_is_a_dosdevice():
    assert prefixlayout.get_real_drive_path(WINE(), "d") == "/prefixes/game/dosdevices/d:"


def test_a_wine_drive_letter_is_lowercased():
    # dosdevices entries are lowercase on disk.
    assert prefixlayout.get_real_drive_path(WINE(), "D") == "/prefixes/game/dosdevices/d:"


def test_an_uppercase_wine_c_drive_is_still_drive_c():
    assert prefixlayout.get_real_drive_path(WINE(), "C") == "/prefixes/game/drive_c"


def test_a_sandboxie_drive_is_uppercased():
    assert prefixlayout.get_real_drive_path(SANDBOXIE(), "c") == "/prefixes/game/drive/C"


def test_a_sandboxie_secondary_drive_sits_beside_the_first():
    assert prefixlayout.get_real_drive_path(SANDBOXIE(), "d") == "/prefixes/game/drive/D"


def test_a_sandboxie_drive_has_no_colon():
    # Sandboxie names the folder after the bare letter.
    assert ":" not in prefixlayout.get_real_drive_path(SANDBOXIE(), "d")


@pytest.mark.parametrize("prefix", [WINE, SANDBOXIE], ids = ["wine", "sandboxie"])
def test_the_c_drive_shortcut_matches_the_general_lookup(prefix):
    entry = prefix()

    assert prefixlayout.get_real_c_drive_path(entry) == prefixlayout.get_real_drive_path(entry, "c")


def test_a_non_prefix_has_no_drive_path():
    assert prefixlayout.get_real_drive_path(NEITHER(), "c") is None
    assert prefixlayout.get_real_c_drive_path(NEITHER()) is None


def test_wine_and_sandboxie_drives_do_not_coincide():
    assert prefixlayout.get_real_drive_path(WINE(), "d") != prefixlayout.get_real_drive_path(SANDBOXIE(), "d")


###########################################################
# Profile paths
###########################################################

def test_the_wine_user_profile_is_under_drive_c():
    path = prefixlayout.get_user_profile_path(WINE())

    assert path.endswith(getpass.getuser())
    assert "drive_c/users" in path.replace("\\", "/")


def test_the_sandboxie_user_profile_is_the_current_user():
    path = prefixlayout.get_user_profile_path(SANDBOXIE())

    assert path.replace("\\", "/").endswith("user/current")


def test_a_non_prefix_has_no_user_profile():
    assert prefixlayout.get_user_profile_path(NEITHER()) is None


def test_the_wine_public_profile_is_a_sibling_of_the_user_profile():
    path = prefixlayout.get_public_profile_path(WINE()).replace("\\", "/")

    assert path.endswith("drive_c/users/Public")


def test_the_sandboxie_public_profile_is_under_the_c_drive():
    path = prefixlayout.get_public_profile_path(SANDBOXIE()).replace("\\", "/")

    assert path.endswith("drive/C/Public")


def test_a_non_prefix_has_no_public_profile():
    assert prefixlayout.get_public_profile_path(NEITHER()) is None


@pytest.mark.parametrize("prefix", [WINE, SANDBOXIE], ids = ["wine", "sandboxie"])
def test_the_public_and_user_profiles_are_distinct(prefix):
    entry = prefix()

    assert prefixlayout.get_public_profile_path(entry) != prefixlayout.get_user_profile_path(entry)


###########################################################
# Prefix selection
###########################################################

def test_an_unnamed_prefix_resolves_to_nothing():
    # Without a name there is no directory to pick under the sandbox root.
    assert prefixlayout.get_prefix(WINE()) is None


def test_a_non_prefix_resolves_to_nothing():
    assert prefixlayout.get_prefix(NEITHER(prefix_name = "game")) is None


def test_a_named_prefix_sits_under_its_runners_sandbox_root(monkeypatch):
    roots = {"Wine": "/sandboxes/wine", "Sandboxie": "C:/Sandbox"}
    monkeypatch.setattr(
        prefixlayout.programs, "get_tool_path_config_value", lambda tool, key: roots[tool])

    assert prefixlayout.get_prefix(WINE(prefix_name = "Game")) == "/sandboxes/wine/Game"
    assert prefixlayout.get_prefix(SANDBOXIE(prefix_name = "Game")) == "C:/Sandbox/Game"
