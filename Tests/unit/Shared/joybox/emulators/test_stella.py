# Imports
import pytest

# Local imports
from joybox.emulators import stella
from emulator_helpers import (
    SETUP_METHODS, Seams, check_passes_the_setup_params_through, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, expected_stored, fetched_releases, stored_releases)


###########################################################
# Stella
#
# An Atari 2600 program: the Windows build comes from GitHub releases and the
# Linux build is an AppImage built from source.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, stella)


def test_identity():
    emulator = stella.Stella()

    assert emulator.get_name() == "Stella"
    assert emulator.get_platforms() == []
    assert emulator.get_config()["Stella"]["program"] == {
        "windows": "Stella/windows/Stella.exe", "linux": "Stella/linux/Stella.AppImage"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_github_release", "stella", "/install/Stella/windows"),
        ("build_appimage_from_source", "https://github.com/NearlyTRex/Stella.git", "/install/Stella/linux")]
    assert seams.releases.values("search_file") == ["64-bit/Stella.exe", None]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("Stella")
    assert seams.releases.values("search_file") == ["64-bit/Stella.exe", None]


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
