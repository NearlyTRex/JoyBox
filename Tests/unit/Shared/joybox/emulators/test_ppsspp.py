# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import ppsspp
from emulator_helpers import (
    SETUP_METHODS, Seams, check_configure_passes_the_setup_params_through,
    check_launch_passes_the_game_and_options_through, check_passes_the_setup_params_through,
    check_skips_platforms_that_are_not_wanted, check_stops_at_the_failed_call,
    check_stops_when_a_config_file_cannot_be_written, check_writes_every_config_file, expected_stored,
    fetched_releases, launch_cmd, stored_releases)


###########################################################
# PPSSPP
#
# A PSP program: the Windows build is scraped from the project's download page
# and the Linux build is an AppImage built from source.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, ppsspp)


def test_identity():
    emulator = ppsspp.PPSSPP()

    assert emulator.get_name() == "PPSSPP"
    assert emulator.get_platforms() == [
        config.Platform.SONY_PLAYSTATION_NETWORK_PSP,
        config.Platform.SONY_PLAYSTATION_NETWORK_PSPM,
        config.Platform.SONY_PLAYSTATION_PORTABLE]
    assert emulator.get_config()["PPSSPP"]["program"] == {
        "windows": "PPSSPP/windows/PPSSPPWindows64.exe", "linux": "PPSSPP/linux/PPSSPP.AppImage"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_webpage_release", "https://www.ppsspp.org/download", "/install/PPSSPP/windows"),
        ("build_appimage_from_source", "https://github.com/NearlyTRex/PPSSPP.git", "/install/PPSSPP/linux")]
    assert seams.releases.values("search_file") == ["PPSSPPWindows64.exe", None]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("PPSSPP")
    assert seams.releases.values("search_file") == ["PPSSPPWindows64.exe", None]


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
    assert launch_cmd(seams) == ["/bin/PPSSPP", config.token_game_file]


def test_launch_has_no_fullscreen_flag(seams):
    assert launch_cmd(seams, fullscreen = True) == ["/bin/PPSSPP", config.token_game_file]


def test_launch_passes_the_game_and_options_through(seams):
    check_launch_passes_the_game_and_options_through(seams)
