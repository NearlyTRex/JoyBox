# Imports
import pytest

# Local imports
from joybox.emulators import snes9x
from emulator_helpers import (
    SETUP_METHODS, Seams, check_passes_the_setup_params_through, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, expected_stored, fetched_releases, stored_releases)


###########################################################
# Snes9x
#
# A Super Nintendo program: the Windows build and the Linux AppImage both come
# from GitHub releases.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, snes9x)


def test_identity():
    emulator = snes9x.Snes9x()

    assert emulator.get_name() == "Snes9x"
    assert emulator.get_platforms() == []
    assert emulator.get_config()["Snes9x"]["program"] == {
        "windows": "Snes9x/windows/snes9x-x64.exe", "linux": "Snes9x/linux/Snes9x.AppImage"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_github_release", "snes9x", "/install/Snes9x/windows"),
        ("download_github_release", "snes9x", "/install/Snes9x/linux")]
    assert seams.releases.values("search_file") == ["snes9x-x64.exe", None]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("Snes9x")
    assert seams.releases.values("search_file") == ["snes9x-x64.exe", None]


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
