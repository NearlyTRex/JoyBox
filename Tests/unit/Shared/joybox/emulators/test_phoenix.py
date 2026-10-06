# Imports
import pytest

# Local imports
from joybox.emulators import phoenix
from emulator_helpers import (
    SETUP_METHODS, Seams, check_passes_the_setup_params_through, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, expected_stored, stored_releases)


###########################################################
# Phoenix
#
# A Windows-only Jaguar program, run under Wine on Linux, downloaded as a
# plain archive from archive.org.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, phoenix)


def test_identity():
    emulator = phoenix.Phoenix()

    assert emulator.get_name() == "Phoenix"
    assert emulator.get_platforms() == []
    assert emulator.get_config()["Phoenix"]["program"] == {
        "windows": "Phoenix/windows/PhoenixEmuProject.exe", "linux": "Phoenix/windows/PhoenixEmuProject.exe"}


def test_setup_downloads_the_windows_program(seams):
    assert seams.emulator().setup() is True

    assert seams.releases.values(
        "release", "archive_url", "search_file", "install_dir", "backups_dir") == [(
        "download_general_release",
        "https://archive.org/download/PHX_EMU/ph28jag-win64.zip",
        "PhoenixEmuProject.exe",
        "/install/Phoenix/windows",
        "/backup/Phoenix/windows")]


def test_setup_offline_restores_the_windows_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("Phoenix", ["windows"])
    assert seams.releases.values("search_file") == ["PhoenixEmuProject.exe"]


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_passes_the_setup_params_through(seams, method):
    check_passes_the_setup_params_through(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_skips_platforms_that_are_not_wanted(seams, method):
    check_skips_platforms_that_are_not_wanted(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_fails_when_the_release_fails(seams, method):
    check_stops_at_the_failed_call(seams, method, 1)
