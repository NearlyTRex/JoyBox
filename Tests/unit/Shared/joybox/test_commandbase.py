# Imports
import pytest

# Local imports
from joybox import commandbase, config


###########################################################
# Starter command
#
# Almost every command predicate looks at the first segment, so a command given
# as a string has to split before anything is inspected.
###########################################################

def test_the_starter_is_the_first_segment_of_a_list():
    assert commandbase.get_starter_command(["wine", "game.exe"]) == "wine"


def test_the_starter_is_the_first_segment_of_a_string():
    assert commandbase.get_starter_command("wine game.exe") == "wine"


def test_a_quoted_starter_keeps_its_spaces():
    assert commandbase.get_starter_command('"my program" --flag') == '"my program"'


def test_an_empty_command_has_no_starter():
    assert commandbase.get_starter_command("") == ""
    assert commandbase.get_starter_command([]) == ""


def test_a_lone_command_is_only_a_starter():
    assert commandbase.is_only_starter_command("program") is True
    assert commandbase.is_only_starter_command(["program"]) is True


def test_a_command_with_arguments_is_not_only_a_starter():
    assert commandbase.is_only_starter_command("program --flag") is False
    assert commandbase.is_only_starter_command(["program", "--flag"]) is False


###########################################################
# Command type detection
###########################################################

@pytest.mark.parametrize("command", [
    "game.exe",
    ["game.exe"],
    "game.exe -window",
    ["game.exe", "-window"],
    "/path/to/game.EXE",
])
def test_a_windows_executable_is_detected(command):
    assert commandbase.is_windows_executable_command(command) is True


@pytest.mark.parametrize("command", ["game.sh", "./run", ["python", "script.py"]])
def test_a_non_executable_is_not_detected(command):
    assert commandbase.is_windows_executable_command(command) is False


@pytest.mark.parametrize("command", [
    "app.AppImage",
    "app.appimage",
    "/path/to/app.AppImage --flag",
    ["/path/to/app.AppImage", "--flag"],
])
def test_an_appimage_is_detected(command):
    # Detection reads the starter only, so trailing arguments must not hide it.
    assert commandbase.is_appimage_command(command) is True


def test_a_non_appimage_is_not_detected():
    assert commandbase.is_appimage_command("game.exe") is False


@pytest.mark.parametrize("command", [
    "powershell",
    "powershell -Command x",
    "/usr/bin/powershell",
    "C:/Windows/powershell.exe",
    ["powershell", "-NoProfile"],
])
def test_a_powershell_command_is_detected(command):
    assert commandbase.is_powershell_command(command) is True


def test_a_non_powershell_command_is_not_detected():
    assert commandbase.is_powershell_command("bash -c x") is False


###########################################################
# Extension search
###########################################################

def test_an_extension_is_found_anywhere_by_default():
    assert commandbase.is_command_type_found(
        ["wine", "game.exe"], cmd_exts = [".exe"]) is True


def test_a_missing_extension_is_not_found():
    assert commandbase.is_command_type_found(
        ["wine", "game.bin"], cmd_exts = [".exe"]) is False


def test_no_extensions_finds_nothing():
    assert commandbase.is_command_type_found(["game.exe"], cmd_exts = []) is False


def test_extension_matching_ignores_case():
    assert commandbase.is_command_type_found(
        ["game.EXE"], cmd_exts = [".exe"]) is True


def test_a_search_window_limits_which_segments_match():
    # The window is a range of command-list indices.
    command = ["wine", "game.exe"]

    assert commandbase.is_command_type_found(
        command, cmd_exts = [".exe"], search_start = 1, search_len = 1) is True
    assert commandbase.is_command_type_found(
        command, cmd_exts = [".exe"], search_start = 0, search_len = 1) is False


def test_a_search_window_past_the_end_does_not_restrict():
    assert commandbase.is_command_type_found(
        ["wine", "game.exe"], cmd_exts = [".exe"],
        search_start = 99, search_len = 1) is True


###########################################################
# Runnable commands
###########################################################

def test_a_command_on_the_path_is_runnable():
    assert commandbase.is_runnable_command("sh") is True


def test_a_nonexistent_command_is_not_runnable():
    assert commandbase.is_runnable_command("definitely-not-a-real-binary") is False


def test_a_runnable_command_resolves_to_a_path():
    resolved = commandbase.get_runnable_command_path("sh")

    assert resolved and resolved.endswith("sh")


def test_an_unresolvable_command_has_no_path():
    assert commandbase.get_runnable_command_path("definitely-not-a-real-binary") is None


def test_a_search_directory_is_tried_before_the_path(tmp_path):
    local = tmp_path / "sh"
    local.write_text("#!/bin/sh\n")
    local.chmod(0o755)

    resolved = commandbase.get_runnable_command_path("sh", search_dirs = [str(tmp_path)])

    assert resolved == str(local)
