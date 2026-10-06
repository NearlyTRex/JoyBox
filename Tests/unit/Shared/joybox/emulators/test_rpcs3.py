# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import rpcs3
from emulator_helpers import (
    SETUP_METHODS, Game, Seams, check_configure_passes_the_setup_params_through,
    check_extracts_present_archives_to_each_platform, check_launch_passes_the_game_and_options_through,
    check_passes_the_setup_params_through, check_refuses_a_system_file_with_the_wrong_hash,
    check_skips_archives_missing_from_the_locker, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, check_stops_when_a_config_file_cannot_be_written,
    check_stops_when_an_archive_cannot_be_extracted, check_writes_every_config_file, expected_stored,
    fetched_releases, launch_cmd, stored_releases)


###########################################################
# RPCS3
#
# A PlayStation 3 program: both builds come from GitHub releases, configure
# extracts the verified dev_flash archive, and launching a PSN title first
# copies its licence files into the save's exdata dir.
###########################################################

SYSTEM_ARCHIVES = ["dev_flash"]


@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, rpcs3)


def test_identity():
    emulator = rpcs3.RPCS3()

    assert emulator.get_name() == "RPCS3"
    assert emulator.get_platforms() == [
        config.Platform.SONY_PLAYSTATION_3,
        config.Platform.SONY_PLAYSTATION_NETWORK_PS3]
    assert emulator.get_config()["RPCS3"]["program"] == {
        "windows": "RPCS3/windows/rpcs3.exe", "linux": "RPCS3/linux/RPCS3.AppImage"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_github_release", "rpcs3-binaries-win", "/install/RPCS3/windows"),
        ("download_github_release", "rpcs3-binaries-linux", "/install/RPCS3/linux")]
    assert seams.releases.values("search_file") == ["rpcs3.exe", None]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("RPCS3")
    assert seams.releases.values("search_file") == ["rpcs3.exe", None]


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


def test_configure_extracts_the_system_archives_to_each_platform(seams):
    check_extracts_present_archives_to_each_platform(seams, SYSTEM_ARCHIVES)


def test_configure_skips_archives_missing_from_the_locker(seams):
    check_skips_archives_missing_from_the_locker(seams)


def test_configure_stops_when_an_archive_cannot_be_extracted(seams):
    check_stops_when_an_archive_cannot_be_extracted(seams, SYSTEM_ARCHIVES)


def test_configure_refuses_a_system_file_with_the_wrong_hash(seams):
    check_refuses_a_system_file_with_the_wrong_hash(seams)


###########################################################
# Launch
###########################################################

def test_launch_runs_the_program_on_the_game(seams):
    assert launch_cmd(seams) == ["/bin/RPCS3", config.token_game_file]


def test_launch_fullscreen_adds_the_fullscreen_flags(seams):
    assert launch_cmd(seams, fullscreen = True)[2:] == ["--fullscreen", "--no-gui"]


def test_launch_passes_the_game_and_options_through(seams):
    check_launch_passes_the_game_and_options_through(seams)


def make_cache(seams, *names):
    for name in names:
        (seams.cache_dir / name).write_text("")


def test_launching_a_psn_title_copies_its_licences_into_exdata(seams):
    make_cache(seams, "game.rap", "data.edat", "game.pkg")
    game = Game(str(seams.cache_dir), config.Platform.SONY_PLAYSTATION_NETWORK_PS3, "/saves/game")

    launch_cmd(seams, game, pretend_run = True)

    assert seams.copied.values("src", "dest") == [
        (str(seams.cache_dir / "data.edat"), "/saves/game/exdata"),
        (str(seams.cache_dir / "game.rap"), "/saves/game/exdata")]
    assert seams.copied.calls[0]["pretend_run"] is True


def test_launching_a_disc_title_copies_no_licences(seams):
    make_cache(seams, "game.rap")
    game = Game(str(seams.cache_dir), config.Platform.SONY_PLAYSTATION_3, "/saves/game")

    launch_cmd(seams, game)

    assert seams.copied.calls == []
