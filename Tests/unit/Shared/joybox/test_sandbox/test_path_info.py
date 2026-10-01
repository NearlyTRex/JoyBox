# Imports
import getpass
import os

# Local imports
from joybox import config, sandbox
from sandbox_helpers import WINE, SANDBOXIE, NEITHER


###########################################################
# Path info inside and around a prefix
#
# Every path a game reads or writes crosses this boundary. A wrong base or
# letter sends a save to a directory the collection never backs up.
###########################################################

SANDBOX = "C:/Sandbox/Game"
USER = getpass.getuser()


def sandboxie():
    return SANDBOXIE(prefix_dir = SANDBOX)


###########################################################
# Rejected input
###########################################################

def test_an_invalid_path_has_no_info():
    assert sandbox.get_prefix_path_info("", WINE(), is_real_path = True) is None


def test_a_prefix_without_a_directory_has_no_info():
    assert sandbox.get_prefix_path_info("/home/user/a", WINE(prefix_dir = None), is_real_path = True) is None


def test_a_prefix_file_outside_any_drive_has_no_virtual_path():
    # The registry hives sit beside the drives and are not reachable from inside.
    assert sandbox.get_prefix_path_info("/prefixes/game/system.reg", WINE(), is_real_path = True) is None


def test_a_dosdevices_folder_without_a_drive_has_no_virtual_path():
    assert sandbox.get_prefix_path_info("/prefixes/game/dosdevices", WINE(), is_real_path = True) is None


def test_the_prefix_itself_has_no_virtual_path():
    assert sandbox.get_prefix_path_info("/prefixes/game", WINE(), is_real_path = True) is None


###########################################################
# Wine
###########################################################

def test_a_wine_real_path_reports_its_drive_base():
    info = sandbox.get_prefix_path_info("/prefixes/game/drive_c/Games/save.dat", WINE(), is_real_path = True)

    assert info["base"] == "/prefixes/game/drive_c"
    assert info["virtual"] == "C:/Games/save.dat"
    assert info["real"] == "/prefixes/game/drive_c/Games/save.dat"


def test_a_wine_dosdevice_path_reports_its_drive_base():
    info = sandbox.get_prefix_path_info("/prefixes/game/dosdevices/d:/Data/a.bin", WINE(), is_real_path = True)

    assert info["base"] == "/prefixes/game/dosdevices/d:"
    assert info["virtual"] == "D:/Data/a.bin"


def test_the_root_of_the_wine_c_drive_is_the_c_root():
    info = sandbox.get_prefix_path_info("/prefixes/game/drive_c", WINE(), is_real_path = True)

    assert info["virtual"] == "C:/"


def test_a_sibling_prefix_is_not_mistaken_for_the_prefix():
    # /prefixes/game2 shares a string prefix with /prefixes/game but is outside it.
    info = sandbox.get_prefix_path_info("/prefixes/game2/drive_c/a", WINE(), is_real_path = True)

    assert info["letter"] == "z"
    assert info["virtual"] == "Z:/prefixes/game2/drive_c/a"


def test_a_wine_virtual_path_on_another_drive_resolves_to_its_dosdevice():
    info = sandbox.get_prefix_path_info("D:/Data/a.bin", WINE(), is_virtual_path = True)

    assert info["is_virtual"] is True
    assert info["real"] == "/prefixes/game/dosdevices/d:/Data/a.bin"


def test_a_host_path_given_as_virtual_is_treated_as_real_under_wine():
    info = sandbox.get_prefix_path_info("/prefixes/game/drive_c/a", WINE(), is_virtual_path = True)

    assert info["is_real"] is True
    assert info["is_virtual"] is False
    assert info["virtual"] == "C:/a"


def test_path_info_reports_the_prefix_kind():
    info = sandbox.get_prefix_path_info("C:/a", WINE(), is_virtual_path = True)

    assert info["is_wine"] is True
    assert info["is_sandboxie"] is False
    assert info["prefix"] == "/prefixes/game"
    assert info["extra"] == ""


def test_path_info_leaves_the_callers_options_alone():
    entry = WINE(prefix_dir = "/prefixes//game/")
    sandbox.get_prefix_path_info("C:/a", entry, is_virtual_path = True)

    assert entry.get_prefix_dir() == "/prefixes//game/"


###########################################################
# Sandboxie
###########################################################

def test_a_sandboxie_virtual_path_resolves_under_its_drive_folder():
    real = sandbox.translate_virtual_path_to_real_path("C:/Games/save.dat", sandboxie())

    assert real == SANDBOX + "/drive/C/Games/save.dat"


def test_a_sandboxie_virtual_path_resolves_to_the_same_folder_as_the_drive_lookup():
    real = sandbox.translate_virtual_path_to_real_path("D:/Data", sandboxie())

    assert real == sandbox.get_real_drive_path(sandboxie(), "d") + "/Data"


def test_a_sandboxie_real_drive_path_translates_back():
    virtual = sandbox.translate_real_path_to_virtual_path(SANDBOX + "/drive/D/Data/a.bin", sandboxie())

    assert virtual == "D:/Data/a.bin"


def test_a_sandboxie_user_path_resolves_into_the_current_user_folder():
    real = sandbox.translate_virtual_path_to_real_path("C:/Users/%s/Documents/save.dat" % USER, sandboxie())

    assert real == SANDBOX + "/user/current/Documents/save.dat"


def test_a_sandboxie_user_path_reports_the_user_folder_as_extra():
    info = sandbox.get_prefix_path_info("C:/Users/%s/Documents" % USER, sandboxie(), is_virtual_path = True)

    assert info["extra"] == os.path.join("Users", USER)
    assert info["offset"] == "Documents"


def test_a_sandboxie_user_folder_translates_back_to_the_user_path():
    virtual = sandbox.translate_real_path_to_virtual_path(SANDBOX + "/user/current/Documents/save.dat", sandboxie())

    assert virtual == "C:/Users/%s/Documents/save.dat" % USER


def test_a_sandboxie_user_path_round_trips():
    virtual = "C:/Users/%s/Saved Games/slot1.sav" % USER

    real = sandbox.translate_virtual_path_to_real_path(virtual, sandboxie())

    assert sandbox.translate_real_path_to_virtual_path(real, sandboxie()) == virtual


def test_a_similarly_named_user_is_not_the_current_user():
    real = sandbox.translate_virtual_path_to_real_path("C:/Users/%sx/a" % USER, sandboxie())

    assert real == SANDBOX + "/drive/C/Users/%sx/a" % USER


def test_a_host_path_outside_the_sandbox_keeps_its_own_virtual_path():
    # Sandboxie shows the host drives unchanged; no user folder is spliced in.
    info = sandbox.get_prefix_path_info("C:/Games/save.dat", sandboxie(), is_real_path = True)

    assert info["virtual"] == "C:/Games/save.dat"
    assert info["extra"] == ""


def test_a_sandbox_folder_outside_any_drive_has_no_virtual_path():
    assert sandbox.get_prefix_path_info(SANDBOX + "/RegHive", sandboxie(), is_real_path = True) is None


###########################################################
# Neither
###########################################################

def test_a_non_prefix_reaches_host_paths_through_z_on_wine_platforms(monkeypatch):
    monkeypatch.setattr(sandbox.platform_info, "is_wine_platform", lambda: True)

    info = sandbox.get_prefix_path_info("/home/user/a", NEITHER(), is_virtual_path = True)

    assert info["is_real"] is True
    assert info["virtual"] == "Z:/home/user/a"


def test_a_non_prefix_keeps_the_drive_letter_elsewhere(monkeypatch):
    monkeypatch.setattr(sandbox.platform_info, "is_wine_platform", lambda: False)

    info = sandbox.get_prefix_path_info("D:/Games/a", NEITHER(), is_real_path = True)

    assert info["letter"] == "d"
    assert info["virtual"] == "D:/Games/a"


###########################################################
# Translation without a prefix directory
###########################################################

def test_a_missing_prefix_directory_is_looked_up_by_name(monkeypatch):
    monkeypatch.setattr(
        sandbox.programs, "get_tool_path_config_value", lambda tool, key: "/sandboxes")
    entry = WINE(prefix_dir = None, prefix_name = config.PrefixType.GAME)

    real = sandbox.translate_virtual_path_to_real_path("C:/a", entry)

    assert real == "/sandboxes/Game/drive_c/a"


def test_looking_up_the_prefix_does_not_change_the_callers_options(monkeypatch):
    monkeypatch.setattr(
        sandbox.programs, "get_tool_path_config_value", lambda tool, key: "/sandboxes")
    entry = WINE(prefix_dir = None, prefix_name = config.PrefixType.GAME)

    sandbox.translate_real_path_to_virtual_path("/sandboxes/Game/drive_c/a", entry)

    assert entry.get_prefix_dir() is None


def test_a_real_path_translates_through_a_looked_up_prefix(monkeypatch):
    monkeypatch.setattr(
        sandbox.programs, "get_tool_path_config_value", lambda tool, key: "/sandboxes")
    entry = WINE(prefix_dir = None, prefix_name = config.PrefixType.GAME)

    assert sandbox.translate_real_path_to_virtual_path("/sandboxes/Game/drive_c/a", entry) == "C:/a"


def test_an_unnamed_prefix_without_a_directory_translates_to_nothing():
    entry = WINE(prefix_dir = None)

    assert sandbox.translate_virtual_path_to_real_path("C:/a", entry) is None
    assert sandbox.translate_real_path_to_virtual_path("/a", entry) is None


def test_a_virtual_path_without_a_drive_has_no_real_path():
    assert sandbox.translate_virtual_path_to_real_path("Games/save.dat", sandboxie()) is None


def test_a_prefix_file_outside_any_drive_translates_to_nothing():
    assert sandbox.translate_real_path_to_virtual_path("/prefixes/game/system.reg", WINE()) is None


def test_an_unusable_prefix_directory_translates_to_nothing():
    entry = WINE(prefix_dir = "/" + "a" * 5000)

    assert sandbox.translate_virtual_path_to_real_path("C:/a", entry) is None


def test_a_real_path_is_untouched_without_a_prefix():
    assert sandbox.translate_real_path_to_virtual_path("/home/user/a", NEITHER()) == "/home/user/a"


def test_a_path_must_be_either_virtual_or_real():
    assert sandbox.get_prefix_path_info("C:/a", WINE()) is None
    assert sandbox.get_prefix_path_info("C:/a", WINE(), is_virtual_path = True, is_real_path = True) is None


def test_a_non_prefix_does_not_parse_drives_inside_its_directory(monkeypatch):
    monkeypatch.setattr(sandbox.platform_info, "is_wine_platform", lambda: True)

    info = sandbox.get_prefix_path_info("/prefixes/game/drive_c/a", NEITHER(), is_real_path = True)

    assert info["virtual"] == "Z:/prefixes/game/drive_c/a"
