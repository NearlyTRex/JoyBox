# Imports
import pytest

# Local imports
from joybox.emulators import sheepshaver
from emulator_helpers import (
    SETUP_METHODS, Seams, check_passes_the_setup_params_through, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, expected_stored, fetched_releases, stored_releases)


###########################################################
# SheepShaver
#
# A classic Mac OS program: the Windows build and the Linux AppImage both come
# from GitHub releases.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, sheepshaver)


def test_identity():
    emulator = sheepshaver.SheepShaver()

    assert emulator.get_name() == "SheepShaver"
    assert emulator.get_platforms() == []
    assert emulator.get_config()["SheepShaver"]["program"] == {
        "windows": "SheepShaver/windows/SheepShaver.exe", "linux": "SheepShaver/linux/SheepShaver.AppImage"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_github_release", "MacEmu", "/install/SheepShaver/windows"),
        ("download_github_release", "macemu-appimage-builder", "/install/SheepShaver/linux")]
    assert seams.releases.values("search_file") == ["SheepShaver.exe", None]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("SheepShaver")
    assert seams.releases.values("search_file") == ["SheepShaver.exe", None]


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
