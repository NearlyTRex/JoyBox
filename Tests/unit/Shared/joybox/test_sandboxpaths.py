# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, sandbox, sandboxpaths
from sandbox_helpers import options, WINE, NEITHER, sandboxie


###########################################################
# Translating paths across the prefix boundary
###########################################################

def test_a_path_inside_the_prefix_keeps_its_drive_letter(wine_prefix):
    real = os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games", "save.dat")

    info = sandbox.get_prefix_path_info(real, wine_prefix, is_real_path = True)

    assert info["letter"] == "c"
    assert info["offset"] == os.path.join("Games", "save.dat")


def test_a_secondary_drive_inside_the_prefix_is_recognised(wine_prefix):
    real = os.path.join(wine_prefix.get_prefix_dir(), "dosdevices", "d:", "Games", "save.dat")

    info = sandbox.get_prefix_path_info(real, wine_prefix, is_real_path = True)

    assert info["letter"] == "d"
    assert info["offset"] == os.path.join("Games", "save.dat")


def test_a_path_outside_the_prefix_is_reached_through_the_z_drive(wine_prefix):
    # Wine maps the host filesystem onto Z:, and building that mapping used to
    # raise instead of returning a path.
    info = sandbox.get_prefix_path_info("/home/user/saves/file.sav", wine_prefix, is_real_path = True)

    assert info["letter"] == "z"
    assert info["virtual"].startswith("Z:")


def test_a_virtual_path_translates_to_a_real_one(wine_prefix):
    real = sandboxpaths.translate_virtual_path_to_real_path("C:/Games/save.dat", wine_prefix)

    assert real == os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games", "save.dat")


def test_a_real_path_translates_back_to_a_virtual_one(wine_prefix):
    real = os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games", "save.dat")

    assert sandboxpaths.translate_real_path_to_virtual_path(real, wine_prefix) == "C:/Games/save.dat"


def test_a_translation_round_trips(wine_prefix):
    virtual = "C:/Games/Deep/save.dat"

    real = sandboxpaths.translate_virtual_path_to_real_path(virtual, wine_prefix)

    assert sandboxpaths.translate_real_path_to_virtual_path(real, wine_prefix) == virtual


def test_a_path_is_untouched_without_a_prefix():
    plain = options()

    assert sandboxpaths.translate_virtual_path_to_real_path("/home/user/save.dat", plain) == \
        "/home/user/save.dat"


###########################################################
# Bringing results back out of the sandbox
###########################################################

def test_a_file_written_inside_the_prefix_is_moved_out(wine_prefix, monkeypatch):
    # The game wrote to its virtual C: drive; the caller asked for the file at
    # the path it used, not the one inside the prefix.
    moved = []
    monkeypatch.setattr(
        sandbox.fileops, "move_file_or_directory",
        lambda src, dest, **kwargs: moved.append((src, dest)))
    inside = os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games")
    os.makedirs(inside)
    with open(os.path.join(inside, "save.dat"), "w", encoding = "utf-8") as handle:
        handle.write("payload")

    sandboxpaths.transfer_from_sandbox("C:/Games/save.dat", wine_prefix)

    assert moved == [(os.path.join(inside, "save.dat"), "C:/Games/save.dat")]


def test_a_copy_can_be_left_behind_in_the_sandbox(wine_prefix, tmp_path, monkeypatch):
    # A game that keeps running expects its own save to still be there.
    copied = []
    monkeypatch.setattr(
        sandbox.fileops, "copy_file_or_directory",
        lambda src, dest, **kwargs: copied.append((src, dest)))
    inside = os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games")
    os.makedirs(inside)
    with open(os.path.join(inside, "save.dat"), "w", encoding = "utf-8") as handle:
        handle.write("payload")

    sandboxpaths.transfer_from_sandbox("C:/Games/save.dat", wine_prefix, keep_in_sandbox = True)

    assert copied == [(os.path.join(inside, "save.dat"), "C:/Games/save.dat")]


def test_a_directory_is_transferred_by_its_contents(wine_prefix, monkeypatch):
    moved = []
    monkeypatch.setattr(
        sandbox.fileops, "move_contents",
        lambda src, dest, **kwargs: moved.append((src, dest)))
    inside = os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games")
    os.makedirs(inside)

    sandboxpaths.transfer_from_sandbox("C:/Games", wine_prefix)

    assert moved == [(inside, "C:/Games")]


@pytest.fixture
def transfers(monkeypatch):
    # Every move or copy out of the sandbox, by the fileops helper that made it
    made = []
    for name in ["move_file_or_directory", "move_contents", "copy_file_or_directory", "copy_contents"]:
        monkeypatch.setattr(
            sandbox.fileops, name, lambda src, dest, name = name, **kwargs: made.append((name, src, dest)))
    return made


def test_nothing_is_transferred_when_the_prefix_holds_nothing(wine_prefix, transfers):
    sandboxpaths.transfer_from_sandbox("C:/Games/save.dat", wine_prefix)

    assert transfers == []


def test_nothing_is_transferred_without_a_prefix(transfers):
    # A path outside a prefix is already where it belongs.
    sandboxpaths.transfer_from_sandbox("/home/user/save.dat", options())

    assert transfers == []


def test_a_directory_left_in_the_sandbox_is_copied_by_its_contents(wine_prefix, monkeypatch):
    copied = []
    monkeypatch.setattr(
        sandbox.fileops, "copy_contents",
        lambda src, dest, **kwargs: copied.append((src, dest)))
    inside = os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games")
    os.makedirs(inside)

    sandboxpaths.transfer_from_sandbox("C:/Games", wine_prefix, keep_in_sandbox = True)

    assert copied == [(inside, "C:/Games")]


def test_a_host_path_seen_through_the_sandbox_is_not_transferred(wine_prefix, transfers, monkeypatch):
    monkeypatch.setattr(sandboxpaths, "translate_virtual_path_to_real_path", lambda path, options: path)

    sandboxpaths.transfer_from_sandbox("/home/user/save.dat", wine_prefix)

    assert transfers == []


def test_an_untranslatable_path_is_not_transferred(transfers):
    sandboxpaths.transfer_from_sandbox("Games/save.dat", options(sandboxie = True, prefix_dir = "C:/Sandbox/Game"))

    assert transfers == []


###########################################################
# Translating a path handed to a sandboxed program
###########################################################

@pytest.fixture
def emulator(monkeypatch):
    monkeypatch.setattr(sandbox.programs, "is_program_name_tool", lambda name: name == "7-Zip")
    monkeypatch.setattr(sandbox.programs, "is_program_name_emulator", lambda name: name == "Dolphin")
    monkeypatch.setattr(sandbox.programs, "get_tool_path_config_value", lambda tool, key: "/sandboxes")


def test_tools_and_emulators_have_their_own_prefixes(emulator):
    assert sandboxpaths.get_program_prefix_name("7-Zip") == config.PrefixType.TOOL
    assert sandboxpaths.get_program_prefix_name("Dolphin") == config.PrefixType.EMULATOR
    assert sandboxpaths.get_program_prefix_name("Unknown") is None


def test_a_path_for_a_program_run_via_wine_is_translated(wine_platform, cached_game, emulator):
    translated = sandboxpaths.translate_path_if_necessary("/home/user/disc.iso", "Dolphin.exe", "Dolphin")

    assert translated == "Z:/home/user/disc.iso"


def test_a_path_inside_the_programs_prefix_maps_to_its_c_drive(wine_platform, cached_game, emulator):
    translated = sandboxpaths.translate_path_if_necessary(
        "/sandboxes/Tool/drive_c/out.7z", "7z.exe", "7-Zip")

    assert translated == "C:/out.7z"


def test_a_path_for_a_native_program_is_untouched(wine_platform, emulator, monkeypatch):
    monkeypatch.setattr(sandbox.commandbase, "is_windows_executable_command", lambda cmd: False)

    assert sandboxpaths.translate_path_if_necessary("/home/user/disc.iso", "dolphin", "Dolphin") == \
        "/home/user/disc.iso"


###########################################################
# Translation without a prefix directory
###########################################################

def test_a_missing_prefix_directory_is_looked_up_by_name(monkeypatch):
    monkeypatch.setattr(
        sandbox.programs, "get_tool_path_config_value", lambda tool, key: "/sandboxes")
    entry = WINE(prefix_dir = None, prefix_name = config.PrefixType.GAME)

    real = sandboxpaths.translate_virtual_path_to_real_path("C:/a", entry)

    assert real == "/sandboxes/Game/drive_c/a"


def test_looking_up_the_prefix_does_not_change_the_callers_options(monkeypatch):
    monkeypatch.setattr(
        sandbox.programs, "get_tool_path_config_value", lambda tool, key: "/sandboxes")
    entry = WINE(prefix_dir = None, prefix_name = config.PrefixType.GAME)

    sandboxpaths.translate_real_path_to_virtual_path("/sandboxes/Game/drive_c/a", entry)

    assert entry.get_prefix_dir() is None


def test_a_real_path_translates_through_a_looked_up_prefix(monkeypatch):
    monkeypatch.setattr(
        sandbox.programs, "get_tool_path_config_value", lambda tool, key: "/sandboxes")
    entry = WINE(prefix_dir = None, prefix_name = config.PrefixType.GAME)

    assert sandboxpaths.translate_real_path_to_virtual_path("/sandboxes/Game/drive_c/a", entry) == "C:/a"


def test_an_unnamed_prefix_without_a_directory_translates_to_nothing():
    entry = WINE(prefix_dir = None)

    assert sandboxpaths.translate_virtual_path_to_real_path("C:/a", entry) is None
    assert sandboxpaths.translate_real_path_to_virtual_path("/a", entry) is None


def test_a_virtual_path_without_a_drive_has_no_real_path():
    assert sandboxpaths.translate_virtual_path_to_real_path("Games/save.dat", sandboxie()) is None


def test_a_prefix_file_outside_any_drive_translates_to_nothing():
    assert sandboxpaths.translate_real_path_to_virtual_path("/prefixes/game/system.reg", WINE()) is None


def test_an_unusable_prefix_directory_translates_to_nothing():
    entry = WINE(prefix_dir = "/" + "a" * 5000)

    assert sandboxpaths.translate_virtual_path_to_real_path("C:/a", entry) is None


def test_a_real_path_is_untouched_without_a_prefix():
    assert sandboxpaths.translate_real_path_to_virtual_path("/home/user/a", NEITHER()) == "/home/user/a"


def test_a_path_must_be_either_virtual_or_real():
    assert sandbox.get_prefix_path_info("C:/a", WINE()) is None
    assert sandbox.get_prefix_path_info("C:/a", WINE(), is_virtual_path = True, is_real_path = True) is None


def test_a_non_prefix_does_not_parse_drives_inside_its_directory(monkeypatch):
    monkeypatch.setattr(sandbox.platform_info, "is_wine_platform", lambda: True)

    info = sandbox.get_prefix_path_info("/prefixes/game/drive_c/a", NEITHER(), is_real_path = True)

    assert info["virtual"] == "Z:/prefixes/game/drive_c/a"
