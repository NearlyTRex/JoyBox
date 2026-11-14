# Imports
import re

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.packages.node import node
from fakes import RecordingConnection

# An npm package name, optionally @scoped
NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
ENTRIES = [(environment, package) for environment, package_list in node.items() for package in package_list]


def test_every_environment_has_a_list():
    assert set(node) == set(constants.EnvironmentType)


def test_no_duplicate_ids():
    duplicates = {
        environment: sorted({package["id"] for package in package_list
                             if [other["id"] for other in package_list].count(package["id"]) > 1})
        for environment, package_list in node.items()}

    assert not any(duplicates.values()), f"duplicate node ids: {duplicates}"


@pytest.mark.parametrize("environment, package", ENTRIES, ids = str)
def test_every_entry_is_described(environment, package):
    assert {field: package.get(field) for field in ["id", "name", "description", "category"] if not package.get(field)} == {}


@pytest.mark.parametrize("environment, package", ENTRIES, ids = str)
def test_ids_are_npm_package_names(environment, package):
    assert NPM_NAME.match(package["id"]), package["id"]


def test_the_supported_environment_has_packages(isolated_settings):
    supported = installers.Node(RecordingConnection()).get_supported_environments()

    assert [environment for environment in supported if not node[environment]] == []
