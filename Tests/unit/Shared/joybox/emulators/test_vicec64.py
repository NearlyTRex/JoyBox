# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import vicec64
from emulator_helpers import (
    SETUP_METHODS, Seams, check_configure_passes_the_setup_params_through,
    check_launch_passes_the_game_and_options_through, check_passes_the_setup_params_through,
    check_skips_platforms_that_are_not_wanted, check_stops_at_the_failed_call,
    check_stops_when_a_config_file_cannot_be_written, check_writes_every_config_file, expected_stored,
    fetched_releases, launch_cmd, stored_releases)


###########################################################
# VICE-C64
#
# A Commodore 64 program: the Windows build comes from GitHub releases and the
# Linux build is an AppImage built from source.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, vicec64)


def test_identity():
    emulator = vicec64.ViceC64()

    assert emulator.get_name() == "VICE-C64"
    assert emulator.get_platforms() == [
        config.Platform.OTHER_COMMODORE_64]
    assert emulator.get_config()["VICE-C64"]["program"] == {
        "windows": "VICE-C64/windows/x64sc.exe", "linux": "VICE-C64/linux/VICE-C64.AppImage"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_github_release", "svn-mirror", "/install/VICE-C64/windows"),
        ("build_appimage_from_source", "https://github.com/NearlyTRex/ViceC64.git", "/install/VICE-C64/linux")]
    assert seams.releases.values("search_file") == ["x64sc.exe", None]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("VICE-C64")
    assert seams.releases.values("search_file") == ["x64sc.exe", None]


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_passes_the_setup_params_through(seams, method):
    check_passes_the_setup_params_through(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_skips_platforms_that_are_not_wanted(seams, method):
    check_skips_platforms_that_are_not_wanted(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
@pytest.mark.parametrize("failing_call", [1, 2])
def test_setup_stops_at_the_first_failure(seams, method, failing_call):
    check_stops_at_the_failed_call(seams, method, failing_call)


###########################################################
# Configure
###########################################################

def test_configure_writes_every_config_file(seams):
    check_writes_every_config_file(seams)


def test_configure_stops_when_a_config_file_cannot_be_written(seams):
    check_stops_when_a_config_file_cannot_be_written(seams)


def test_configure_passes_the_setup_params_through(seams):
    check_configure_passes_the_setup_params_through(seams)


###########################################################
# Launch
###########################################################

def test_launch_runs_the_program_on_the_game(seams):
    assert launch_cmd(seams) == ["/bin/VICE-C64", config.token_game_file]


def test_launch_has_no_fullscreen_flag(seams):
    assert launch_cmd(seams, fullscreen = True) == ["/bin/VICE-C64", config.token_game_file]


def test_launch_passes_the_game_and_options_through(seams):
    check_launch_passes_the_game_and_options_through(seams)
