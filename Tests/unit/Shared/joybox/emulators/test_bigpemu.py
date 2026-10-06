# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import bigpemu
from emulator_helpers import (
    SETUP_METHODS, Seams, check_configure_passes_the_setup_params_through,
    check_launch_passes_the_game_and_options_through, check_passes_the_setup_params_through,
    check_skips_platforms_that_are_not_wanted, check_stops_at_the_failed_call,
    check_stops_when_a_config_file_cannot_be_written, check_writes_every_config_file, expected_stored,
    fetched_releases, launch_cmd, stored_releases)


###########################################################
# BigPEmu
#
# A Windows-only Jaguar program, run under Wine on Linux, scraped from the
# author's download page; it keeps its data beside the program.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, bigpemu)


def test_identity():
    emulator = bigpemu.BigPEmu()

    assert emulator.get_name() == "BigPEmu"
    assert emulator.get_platforms() == [
        config.Platform.OTHER_ATARI_JAGUAR,
        config.Platform.OTHER_ATARI_JAGUAR_CD]
    assert emulator.get_config()["BigPEmu"]["program"] == {
        "windows": "BigPEmu/windows/BigPEmu.exe", "linux": "BigPEmu/windows/BigPEmu.exe"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_webpage_release", "https://www.richwhitehouse.com/jaguar/index.php?content=download", "/install/BigPEmu/windows")]
    assert seams.releases.values("search_file") == ["BigPEmu.exe"]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("BigPEmu", ['windows'])
    assert seams.releases.values("search_file") == ["BigPEmu.exe"]


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_passes_the_setup_params_through(seams, method):
    check_passes_the_setup_params_through(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_skips_platforms_that_are_not_wanted(seams, method):
    check_skips_platforms_that_are_not_wanted(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
@pytest.mark.parametrize("failing_call", [1])
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
    assert launch_cmd(seams) == ["/bin/BigPEmu", config.token_game_file, "-localdata"]


def test_launch_has_no_fullscreen_flag(seams):
    assert launch_cmd(seams, fullscreen = True) == ["/bin/BigPEmu", config.token_game_file, "-localdata"]


def test_launch_passes_the_game_and_options_through(seams):
    check_launch_passes_the_game_and_options_through(seams)
