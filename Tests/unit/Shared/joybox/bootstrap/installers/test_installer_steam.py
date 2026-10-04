# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


def build(**kwargs):
    connection = RecordingConnection(**kwargs)
    return installers.Steam(connection), connection


###########################################################
# Status
###########################################################

def test_only_local_ubuntu_is_supported(isolated_settings):
    steam, _ = build()
    assert steam.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


@pytest.mark.parametrize("present, installed, missing", [
    ([], [], ["steam", "steamcmd"]),
    (["/usr/games/steam"], ["steam"], ["steamcmd"]),
    (["/usr/games/steamcmd"], ["steamcmd"], ["steam"]),
    (["/usr/games/steam", "/usr/games/steamcmd"], ["steam", "steamcmd"], []),
])
def test_status_needs_both_binaries(isolated_settings, present, installed, missing):
    steam, _ = build(existing_paths = present)
    assert steam.get_package_status() == {"installed": installed, "missing": missing}
    assert steam.is_installed() == (not missing)


###########################################################
# Install
###########################################################

def test_install_enables_i386_and_preaccepts_the_license(isolated_settings):
    steam, connection = build()
    assert steam.install()
    assert connection.ran("--add-architecture i386")
    assert connection.ran("install -y steam-installer")
    assert not connection.ran("install -y steam ")
    assert connection.ran("steam/question select I AGREE", "debconf-set-selections")
    assert connection.ran("steam/license note", "debconf-set-selections")
    assert connection.ran("install -y steamcmd")
    assert all(call[2]["sudo"] for call in connection.called("run_blocking"))

    # The license must be accepted before steamcmd's prompt would appear
    strings = connection.command_strings()
    license_index = max(i for i, s in enumerate(strings) if "debconf-set-selections" in s)
    steamcmd_index = next(i for i, s in enumerate(strings) if "install -y steamcmd" in s)
    assert license_index < steamcmd_index


def test_install_falls_back_to_the_steam_package(isolated_settings):
    steam, connection = build(return_codes = {"steam-installer": 1})
    assert steam.install()
    assert connection.ran("install -y steam")
    assert connection.ran("install -y steamcmd")


@pytest.mark.parametrize("return_codes", [
    {"--add-architecture": 1},
    {" update": 1},
    {"steam-installer": 1, "install -y steam": 1},
    {"install -y steamcmd": 1},
])
def test_a_failing_step_stops_the_install(isolated_settings, return_codes):
    steam, _ = build(return_codes = return_codes)
    assert not steam.install()


###########################################################
# Uninstall
###########################################################

def test_uninstall_removes_both_packages(isolated_settings):
    steam, connection = build()
    assert steam.uninstall()
    assert connection.ran("remove -y steamcmd")
    assert connection.ran("remove -y steam-installer steam")
