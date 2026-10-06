# Imports
import pytest

# Local imports
from joybox.emulators import bgb
from emulator_helpers import (
    SETUP_METHODS, Seams, check_passes_the_setup_params_through, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, expected_stored, stored_releases)


###########################################################
# BGB
#
# A Windows-only Game Boy program, run under Wine on Linux, downloaded as a
# plain archive from the author's site.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, bgb)


def test_identity():
    emulator = bgb.BGB()

    assert emulator.get_name() == "BGB"
    assert emulator.get_platforms() == []
    assert emulator.get_config()["BGB"]["program"] == {
        "windows": "BGB/windows/bgb.exe", "linux": "BGB/windows/bgb.exe"}


def test_setup_downloads_the_windows_program(seams):
    assert seams.emulator().setup() is True

    assert seams.releases.values(
        "release", "archive_url", "search_file", "install_dir", "backups_dir") == [(
        "download_general_release",
        "https://bgb.bircd.org/bgb.zip",
        "bgb.exe",
        "/install/BGB/windows",
        "/backup/BGB/windows")]


def test_setup_offline_restores_the_windows_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("BGB", ["windows"])
    assert seams.releases.values("search_file") == ["bgb.exe"]


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_passes_the_setup_params_through(seams, method):
    check_passes_the_setup_params_through(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_skips_platforms_that_are_not_wanted(seams, method):
    check_skips_platforms_that_are_not_wanted(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_fails_when_the_release_fails(seams, method):
    check_stops_at_the_failed_call(seams, method, 1)
