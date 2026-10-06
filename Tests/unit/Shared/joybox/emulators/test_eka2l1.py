# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import eka2l1
from emulator_helpers import (
    SETUP_METHODS, Seams, check_configure_passes_the_setup_params_through,
    check_extracts_present_archives_to_each_platform, check_launch_passes_the_game_and_options_through,
    check_passes_the_setup_params_through, check_refuses_a_system_file_with_the_wrong_hash,
    check_skips_archives_missing_from_the_locker, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, check_stops_when_a_config_file_cannot_be_written,
    check_stops_when_an_archive_cannot_be_extracted, check_writes_every_config_file, expected_stored,
    fetched_releases, launch_cmd, stored_releases)


###########################################################
# EKA2L1
#
# An N-Gage program: both builds come from GitHub releases, and configure
# extracts the verified system data archive into each platform's setup dir.
###########################################################

SYSTEM_ARCHIVES = ["data"]


@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, eka2l1)


def test_identity():
    emulator = eka2l1.EKA2L1()

    assert emulator.get_name() == "EKA2L1"
    assert emulator.get_platforms() == [
        config.Platform.OTHER_NOKIA_NGAGE]
    assert emulator.get_config()["EKA2L1"]["program"] == {
        "windows": "EKA2L1/windows/eka2l1_qt.exe", "linux": "EKA2L1/linux/EKA2L1.AppImage"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_github_release", "EKA2L1", "/install/EKA2L1/windows"),
        ("download_github_release", "EKA2L1", "/install/EKA2L1/linux")]
    assert seams.releases.values("search_file") == ["eka2l1_qt.exe", None]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("EKA2L1")
    assert seams.releases.values("search_file") == ["eka2l1_qt.exe", None]


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
    assert launch_cmd(seams) == ["/bin/EKA2L1", "--mount", config.token_game_dir, "--app", config.token_game_name]


def test_launch_has_no_fullscreen_flag(seams):
    assert launch_cmd(seams, fullscreen = True) == ["/bin/EKA2L1", "--mount", config.token_game_dir, "--app", config.token_game_name]


def test_launch_passes_the_game_and_options_through(seams):
    check_launch_passes_the_game_and_options_through(seams)
