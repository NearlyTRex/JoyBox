# Imports
import pytest

# Local imports
from joybox.emulators import bsnes
from emulator_helpers import (
    SETUP_METHODS, Seams, check_passes_the_setup_params_through, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, expected_stored, stored_releases)


###########################################################
# BSnes
#
# A Windows-only Super Nintendo program, run under Wine on Linux, downloaded
# from its GitHub releases.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, bsnes)


def test_identity():
    emulator = bsnes.BSnes()

    assert emulator.get_name() == "BSnes"
    assert emulator.get_platforms() == []
    assert emulator.get_config()["BSnes"]["program"] == {
        "windows": "BSnes/windows/bsnes.exe", "linux": "BSnes/windows/bsnes.exe"}


def test_setup_downloads_the_windows_program(seams):
    assert seams.emulator().setup() is True

    assert seams.releases.values(
        "release", "github_user", "github_repo", "starts_with", "ends_with", "search_file", "install_dir", "backups_dir") == [(
        "download_github_release",
        "bsnes-emu",
        "bsnes",
        "bsnes-windows",
        ".zip",
        "bsnes.exe",
        "/install/BSnes/windows",
        "/backup/BSnes/windows")]


def test_setup_offline_restores_the_windows_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("BSnes", ["windows"])
    assert seams.releases.values("search_file") == ["bsnes.exe"]


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_passes_the_setup_params_through(seams, method):
    check_passes_the_setup_params_through(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_skips_platforms_that_are_not_wanted(seams, method):
    check_skips_platforms_that_are_not_wanted(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_fails_when_the_release_fails(seams, method):
    check_stops_at_the_failed_call(seams, method, 1)
