# Imports
import pytest

# Local imports
from joybox.emulators import blastem
from emulator_helpers import (
    SETUP_METHODS, Seams, check_passes_the_setup_params_through, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, expected_stored, stored_releases)


###########################################################
# BlastEm
#
# A Windows-only Mega Drive program, run under Wine on Linux, scraped from
# the project's download page.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, blastem)


def test_identity():
    emulator = blastem.BlastEm()

    assert emulator.get_name() == "BlastEm"
    assert emulator.get_platforms() == []
    assert emulator.get_config()["BlastEm"]["program"] == {
        "windows": "BlastEm/windows/blastem.exe", "linux": "BlastEm/windows/blastem.exe"}


def test_setup_downloads_the_windows_program(seams):
    assert seams.emulator().setup() is True

    assert seams.releases.values(
        "release", "webpage_url", "webpage_base_url", "starts_with", "ends_with", "search_file", "install_dir", "backups_dir") == [(
        "download_webpage_release",
        "https://www.retrodev.com/blastem",
        "https://www.retrodev.com/blastem/",
        "https://www.retrodev.com/blastem/blastem-win32",
        ".zip",
        "blastem.exe",
        "/install/BlastEm/windows",
        "/backup/BlastEm/windows")]


def test_setup_offline_restores_the_windows_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("BlastEm", ["windows"])
    assert seams.releases.values("search_file") == ["blastem.exe"]


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_passes_the_setup_params_through(seams, method):
    check_passes_the_setup_params_through(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_skips_platforms_that_are_not_wanted(seams, method):
    check_skips_platforms_that_are_not_wanted(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_fails_when_the_release_fails(seams, method):
    check_stops_at_the_failed_call(seams, method, 1)
