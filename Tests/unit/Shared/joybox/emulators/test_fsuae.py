# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import fsuae
from emulator_helpers import (
    SETUP_METHODS, Seams, check_configure_passes_the_setup_params_through,
    check_copies_system_files_to_each_platform, check_launch_passes_the_game_and_options_through,
    check_passes_the_setup_params_through, check_refuses_a_system_file_with_the_wrong_hash,
    check_skips_platforms_that_are_not_wanted, check_stops_at_the_failed_call,
    check_stops_when_a_config_file_cannot_be_written, check_stops_when_a_system_file_cannot_be_copied,
    check_writes_every_config_file, expected_stored, fetched_releases, launch_cmd, stored_releases)


###########################################################
# FS-UAE
#
# An Amiga program: the Windows build comes from GitHub releases and the Linux
# build is an AppImage built from the source tarball; configure copies the
# verified Kickstart ROMs.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, fsuae)


def test_identity():
    emulator = fsuae.FSUAE()

    assert emulator.get_name() == "FS-UAE"
    assert emulator.get_platforms() == [
        config.Platform.OTHER_COMMODORE_AMIGA]
    assert emulator.get_config()["FS-UAE"]["program"] == {
        "windows": "FS-UAE/windows/Windows/x86-64/fs-uae.exe", "linux": "FS-UAE/linux/FS-UAE.AppImage"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_github_release", "fs-uae", "/install/FS-UAE/windows"),
        ("build_appimage_from_source", "https://github.com/FrodeSolheim/fs-uae/releases/download/v3.1.66/fs-uae-3.1.66.tar.xz", "/install/FS-UAE/linux")]
    assert seams.releases.values("search_file") == ["Plugin.ini", None]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("FS-UAE")
    assert seams.releases.values("search_file") == ["Plugin.ini", None]


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


def test_configure_copies_system_files_to_each_platform(seams):
    check_copies_system_files_to_each_platform(seams)


def test_configure_refuses_a_system_file_with_the_wrong_hash(seams):
    check_refuses_a_system_file_with_the_wrong_hash(seams)


def test_configure_stops_when_a_system_file_cannot_be_copied(seams):
    check_stops_when_a_system_file_cannot_be_copied(seams)


###########################################################
# Launch
###########################################################

def test_launch_runs_the_program_on_the_game(seams):
    assert launch_cmd(seams) == ["/bin/FS-UAE", config.token_game_file]


def test_launch_fullscreen_adds_the_fullscreen_flags(seams):
    assert launch_cmd(seams, fullscreen = True)[2:] == ["--fullscreen=1"]


def test_launch_passes_the_game_and_options_through(seams):
    check_launch_passes_the_game_and_options_through(seams)
