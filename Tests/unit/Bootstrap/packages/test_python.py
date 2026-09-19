# Imports
import pytest

# Local imports
from packages.python import python as python_packages


def test_no_duplicate_ids():
    # LOCAL_WINDOWS extends LOCAL_UBUNTU, so one duplicate shows up twice.
    for environment, package_list in python_packages.items():
        ids = [package["id"] for package in package_list]
        duplicates = sorted({package_id for package_id in ids if ids.count(package_id) > 1})
        assert not duplicates, f"{environment} has duplicate python ids: {duplicates}"


def test_every_package_has_an_id_and_category():
    for environment, package_list in python_packages.items():
        for package in package_list:
            assert package.get("id"), f"{environment} has a package with no id: {package}"
            assert package.get("category"), f"{environment}: {package['id']} has no category"


def test_paramiko_is_declared():
    # Imported lazily, so a missing declaration surfaces partway through a deploy.
    for environment, package_list in python_packages.items():
        ids = {package["id"] for package in package_list}
        if "pytest" in ids:
            assert "paramiko" in ids, f"{environment} declares pytest but not paramiko"
