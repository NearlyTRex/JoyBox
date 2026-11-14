# Imports
import re

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.packages.winget import winget
from fakes import RecordingConnection

# Publisher.Package[.More], no whitespace
WINGET_ID = re.compile(r"^[^\s.]+(\.[^\s.]+)+$")
ENTRIES = [(environment, package) for environment, package_list in winget.items() for package in package_list]


def test_every_environment_has_a_list():
    assert set(winget) == set(constants.EnvironmentType)


def test_no_duplicate_ids():
    # WinGet ids are case-insensitive.
    duplicates = {
        environment: sorted({package for package in package_list
                             if [other.lower() for other in package_list].count(package.lower()) > 1})
        for environment, package_list in winget.items()}

    assert not any(duplicates.values()), f"duplicate winget ids: {duplicates}"


@pytest.mark.parametrize("environment, package", ENTRIES, ids = str)
def test_ids_are_winget_ids(environment, package):
    assert WINGET_ID.match(package), package


def test_packages_are_only_declared_where_winget_installs(isolated_settings):
    supported = installers.WinGet(RecordingConnection()).get_supported_environments()
    populated = [environment for environment, package_list in winget.items() if package_list]

    assert constants.EnvironmentType.LOCAL_WINDOWS in populated
    assert set(populated) <= set(supported), f"declared for {populated}, WinGet supports {supported}"
