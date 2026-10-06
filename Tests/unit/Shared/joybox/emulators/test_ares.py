# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import ares
from emulator_helpers import (
    SETUP_METHODS, Game, PopupQuit, check_launch_passes_the_game_and_options_through, launch_cmd, Seams, check_configure_passes_the_setup_params_through,
    check_copies_system_files_to_each_platform, check_passes_the_setup_params_through,
    check_refuses_a_system_file_with_the_wrong_hash, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, check_stops_when_a_config_file_cannot_be_written,
    check_stops_when_a_system_file_cannot_be_copied, check_writes_every_config_file, expected_stored,
    fetched_releases, stored_releases)


###########################################################
# Ares
#
# A multi-system program: the Windows build comes from GitHub releases and the
# Linux build is an AppImage built from source; configure copies the verified
# BIOS files, and launch picks the ares system matching the game's platform.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, ares)


def test_identity():
    emulator = ares.Ares()

    assert emulator.get_name() == "Ares"
    # Every platform it runs has an ares system to launch it with
    assert set(emulator.get_platforms()) == set(emulator.get_config()["Ares"]["save_sub_dirs"])
    assert emulator.get_config()["Ares"]["program"] == {
        "windows": "Ares/windows/ares.exe", "linux": "Ares/linux/Ares.AppImage"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_github_release", "ares", "/install/Ares/windows"),
        ("build_appimage_from_source", "https://github.com/NearlyTRex/Ares.git", "/install/Ares/linux")]
    assert seams.releases.values("search_file") == ["ares.exe", None]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("Ares")
    assert seams.releases.values("search_file") == ["ares.exe", None]


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

@pytest.mark.parametrize("platform, system", [
    (config.Platform.NINTENDO_64, "Nintendo 64"),
    (config.Platform.NINTENDO_NES, "Famicom"),
    (config.Platform.OTHER_SEGA_GENESIS, "Mega Drive"),
])
def test_launch_runs_the_system_matching_the_game_platform(seams, platform, system):
    game = Game(str(seams.cache_dir), platform)

    assert launch_cmd(seams, game) == ["/bin/Ares", "--system", system, config.token_game_file]


def test_launch_fullscreen_adds_the_fullscreen_flag(seams):
    game = Game(str(seams.cache_dir), config.Platform.NINTENDO_64)

    assert launch_cmd(seams, game, fullscreen = True)[-1] == "--fullscreen"


def test_launch_passes_the_game_and_options_through(seams):
    check_launch_passes_the_game_and_options_through(seams, Game(str(seams.cache_dir), config.Platform.NINTENDO_64))


def test_launch_rejects_a_platform_ares_does_not_run(seams):
    with pytest.raises(PopupQuit):
        seams.emulator().launch(Game(str(seams.cache_dir), config.Platform.SONY_PLAYSTATION))

    assert seams.popups == ["Launch platform not defined"]
    assert seams.launched.calls == []
