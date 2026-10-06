# Imports
import pytest

# Local imports
from joybox.emulators import ryujinx
from emulator_helpers import (
    SETUP_METHODS, Seams, check_configure_passes_the_setup_params_through,
    check_passes_the_setup_params_through, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, check_stops_when_a_config_file_cannot_be_written,
    check_writes_every_config_file, expected_stored, fetched_releases, stored_releases)


###########################################################
# Ryujinx
#
# A Switch program, not in the emulator map: both builds come from GitHub
# releases and configure writes its portable config files.
###########################################################

@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, ryujinx)


def test_identity():
    emulator = ryujinx.Ryujinx()

    assert emulator.get_name() == "Ryujinx"
    assert emulator.get_platforms() == []
    assert emulator.get_config()["Ryujinx"]["program"] == {
        "windows": "Ryujinx/windows/Ryujinx.exe", "linux": "Ryujinx/linux/Ryujinx"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_github_release", "release-channel-master", "/install/Ryujinx/windows"),
        ("download_github_release", "release-channel-master", "/install/Ryujinx/linux")]
    assert seams.releases.values("search_file") == ["Ryujinx.exe", "Ryujinx.sh"]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("Ryujinx")
    assert seams.releases.values("search_file") == ["Ryujinx.exe", "Ryujinx.sh"]


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
