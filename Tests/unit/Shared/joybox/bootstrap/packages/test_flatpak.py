# Imports
import re

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_flatpak
from joybox.bootstrap.packages.flatpak import flatpak
from fakes import RecordingConnection

# Reverse-DNS, at least three elements, none starting with a digit
APP_ID = re.compile(r"^[A-Za-z_][\w-]*(\.[A-Za-z_][\w-]*){2,}$")
ENTRIES = [(environment, package) for environment, package_list in flatpak.items() for package in package_list]


def test_every_environment_has_a_list():
    assert set(flatpak) == set(constants.EnvironmentType)


def test_no_duplicate_ids():
    duplicates = {
        environment: sorted({package["id"] for package in package_list
                             if [other["id"] for other in package_list].count(package["id"]) > 1})
        for environment, package_list in flatpak.items()}

    assert not any(duplicates.values()), f"duplicate flatpak ids: {duplicates}"


@pytest.mark.parametrize("environment, package", ENTRIES, ids = str)
def test_every_entry_is_described(environment, package):
    assert {field: package.get(field) for field in ["id", "name", "description", "category"] if not package.get(field)} == {}


@pytest.mark.parametrize("environment, package", ENTRIES, ids = str)
def test_ids_are_flatpak_app_ids(environment, package):
    assert APP_ID.match(package["id"]), package["id"]


@pytest.mark.parametrize("environment, package", ENTRIES, ids = str)
def test_entries_install_from_flathub(environment, package):
    # The installer only adds the flathub remote.
    assert installer_flatpak.get_flatpak_package_info(package)["repository"] == "flathub"


def test_packages_are_only_declared_where_flatpak_installs(isolated_settings):
    supported = installers.Flatpak(RecordingConnection()).get_supported_environments()
    populated = [environment for environment, package_list in flatpak.items() if package_list]

    assert constants.EnvironmentType.LOCAL_UBUNTU in populated
    assert set(populated) <= set(supported), f"declared for {populated}, Flatpak supports {supported}"
