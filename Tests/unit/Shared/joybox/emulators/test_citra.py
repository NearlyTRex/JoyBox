# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import citra
from emulator_helpers import (
    make_packages, SETUP_METHODS, Seams, check_configure_passes_the_setup_params_through,
    check_extracts_present_archives_to_each_platform, check_launch_passes_the_game_and_options_through,
    check_passes_the_setup_params_through, check_refuses_a_system_file_with_the_wrong_hash,
    check_skips_archives_missing_from_the_locker, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, check_stops_when_a_config_file_cannot_be_written,
    check_stops_when_an_archive_cannot_be_extracted, check_writes_every_config_file, expected_stored,
    launch_cmd, stored_releases)


###########################################################
# Citra
#
# A 3DS program restored only from stored builds, skipped when missing; configure
# extracts the verified NAND and system data archives, and add-ons are CIAs
# installed into the emulated SD card.
###########################################################

SYSTEM_ARCHIVES = ["nand", "sysdata"]


@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, citra)


def test_identity():
    emulator = citra.Citra()

    assert emulator.get_name() == "Citra"
    assert emulator.get_platforms() == [
        config.Platform.NINTENDO_3DS,
        config.Platform.NINTENDO_3DS_APPS,
        config.Platform.NINTENDO_3DS_ESHOP]
    assert emulator.get_config()["Citra"]["program"] == {
        "windows": "Citra/windows/citra-qt.exe", "linux": "Citra/linux/citra-qt.AppImage"}


###########################################################
# Setup
###########################################################

@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_restores_the_stored_builds(seams, method):
    # There is nothing left to download, so online and offline setup agree
    assert getattr(seams.emulator(), method)() is True

    assert stored_releases(seams) == expected_stored("Citra")
    assert seams.releases.values("search_file") == ["citra-qt.exe", "citra-qt.AppImage"]
    assert all(seams.releases.values("skip_if_missing"))


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
    assert launch_cmd(seams) == ["/bin/Citra", config.token_game_file]


def test_launch_has_no_fullscreen_flag(seams):
    assert launch_cmd(seams, fullscreen = True) == ["/bin/Citra", config.token_game_file]


def test_launch_passes_the_game_and_options_through(seams):
    check_launch_passes_the_game_and_options_through(seams)


###########################################################
# Add-ons
###########################################################

def test_install_addons_installs_each_cia_into_the_sd_card(seams, tmp_path):
    installed = seams.fake(citra.nintendo, "install_3ds_cia")
    dlc = make_packages(tmp_path / "dlc", "dlc.cia", "readme.txt")
    update = make_packages(tmp_path / "update", "v1.cia")

    assert seams.emulator().install_addons(dlc_dirs = [dlc], update_dirs = [update], verbose = True) is True

    assert installed.values("src_3ds_file", "sdmc_dir") == [
        (dlc + "/dlc.cia", "/emu/Citra/setup_dir/None/sdmc"),
        (update + "/v1.cia", "/emu/Citra/setup_dir/None/sdmc")]
    assert installed.calls[0]["verbose"] is True


def test_install_addons_stops_at_the_first_failed_cia(seams, tmp_path):
    installed = seams.fake(citra.nintendo, "install_3ds_cia")
    installed.failures.add(1)
    dlc = make_packages(tmp_path / "dlc", "a.cia", "b.cia")

    assert seams.emulator().install_addons(dlc_dirs = [dlc]) is False
    assert len(installed.calls) == 1
