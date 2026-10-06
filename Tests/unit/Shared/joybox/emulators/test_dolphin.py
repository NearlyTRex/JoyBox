# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import dolphin
from emulator_helpers import (
    SETUP_METHODS, Seams, check_configure_passes_the_setup_params_through,
    check_extracts_present_archives_to_each_platform, check_launch_passes_the_game_and_options_through,
    check_passes_the_setup_params_through, check_refuses_a_system_file_with_the_wrong_hash,
    check_skips_archives_missing_from_the_locker, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, check_stops_when_a_config_file_cannot_be_written,
    check_stops_when_an_archive_cannot_be_extracted, check_writes_every_config_file, expected_stored,
    fetched_releases, launch_cmd, stored_releases)


###########################################################
# Dolphin
#
# A GameCube and Wii program: the Windows build is scraped from the download
# page and the Linux build is an AppImage built from source; configure
# extracts the verified Wii NAND archive.
###########################################################

SYSTEM_ARCHIVES = ["Wii"]


@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, dolphin)


def test_identity():
    emulator = dolphin.Dolphin()

    assert emulator.get_name() == "Dolphin"
    assert emulator.get_platforms() == [
        config.Platform.NINTENDO_GAMECUBE,
        config.Platform.NINTENDO_WII,
        config.Platform.NINTENDO_WIIWARE]
    assert emulator.get_config()["Dolphin"]["program"] == {
        "windows": "Dolphin/windows/Dolphin.exe", "linux": "Dolphin/linux/Dolphin.AppImage"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_webpage_release", "https://dolphin-emu.org/download", "/install/Dolphin/windows"),
        ("build_appimage_from_source", "https://github.com/NearlyTRex/Dolphin.git", "/install/Dolphin/linux")]
    assert seams.releases.values("search_file") == ["Dolphin.exe", None]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("Dolphin")
    assert seams.releases.values("search_file") == ["Dolphin.exe", None]


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
    assert launch_cmd(seams) == ["/bin/Dolphin", config.token_game_file]


def test_launch_fullscreen_adds_the_fullscreen_flags(seams):
    assert launch_cmd(seams, fullscreen = True)[2:] == ["--config", "Dolphin.Display.Fullscreen=True"]


def test_launch_passes_the_game_and_options_through(seams):
    check_launch_passes_the_game_and_options_through(seams)


###########################################################
# Add-ons
###########################################################

def test_install_addons_succeeds_for_wad_packages(seams, tmp_path):
    dlc = tmp_path / "dlc"
    dlc.mkdir()
    (dlc / "channel.wad").write_text("")

    assert seams.emulator().install_addons(dlc_dirs = [str(dlc)], update_dirs = [str(dlc)]) is True
    assert seams.copied.calls == seams.extracted.calls == []
