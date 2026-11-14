# Imports
import re

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.packages.cargo import cargo, rust_targets
from fakes import RecordingConnection

LISTS = {"cargo": cargo, "rust_targets": rust_targets}
CRATE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


def entries(lists):
    return [(list_name, environment, package) for list_name, by_environment in lists.items()
            for environment, package_list in by_environment.items() for package in package_list]


@pytest.mark.parametrize("list_name", LISTS)
def test_every_environment_has_a_list(list_name):
    assert set(LISTS[list_name]) == set(constants.EnvironmentType)


@pytest.mark.parametrize("list_name", LISTS)
def test_no_duplicate_ids(list_name):
    duplicates = {
        environment: sorted({package["id"] for package in package_list
                             if [other["id"] for other in package_list].count(package["id"]) > 1})
        for environment, package_list in LISTS[list_name].items()}

    assert not any(duplicates.values()), f"duplicate {list_name} ids: {duplicates}"


@pytest.mark.parametrize("list_name, environment, package", entries(LISTS), ids = str)
def test_every_entry_is_described(list_name, environment, package):
    assert {field: package.get(field) for field in ["id", "name", "description", "category"] if not package.get(field)} == {}


@pytest.mark.parametrize("package", cargo[constants.EnvironmentType.LOCAL_UBUNTU], ids = lambda package: package["id"])
def test_crate_ids_are_crate_names(package):
    assert CRATE_NAME.match(package["id"]), package["id"]


@pytest.mark.parametrize("target", rust_targets[constants.EnvironmentType.LOCAL_UBUNTU], ids = lambda target: target["id"])
def test_target_ids_are_target_triples(target):
    # arch-vendor-os[-env]
    assert len(target["id"].split("-")) >= 3, target["id"]


@pytest.mark.parametrize("list_name", LISTS)
def test_lists_are_only_declared_where_rust_installs(isolated_settings, list_name):
    supported = installers.Rust(RecordingConnection()).get_supported_environments()
    populated = [environment for environment, package_list in LISTS[list_name].items() if package_list]

    assert populated, f"{list_name} is empty everywhere"
    assert set(populated) <= set(supported), f"{list_name} declared for {populated}, Rust supports {supported}"


def test_the_msvc_target_comes_with_the_xwin_tools():
    # cargo xwin builds the msvc target from the CRT and SDK that xwin fetches.
    for environment, targets in rust_targets.items():
        crates = {package["id"] for package in cargo[environment]}
        if any(target["id"].endswith("-windows-msvc") for target in targets):
            assert {"cargo-xwin", "xwin"} <= crates, environment
    assert any(target["id"].endswith("-windows-msvc") for target in rust_targets[constants.EnvironmentType.LOCAL_UBUNTU])
