# Imports
import os

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
from joybox.bootstrap.packages.aptget import aptget


def parse_package_text_file(path):
    # serverpackages.txt is a plain list with # comments
    entries = []
    with open(path, "r") as package_file:
        for line in package_file:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line)
    return entries


def test_no_duplicate_ids():
    for environment, package_list in aptget.items():
        ids = [package["id"] for package in package_list]
        duplicates = sorted({package_id for package_id in ids if ids.count(package_id) > 1})
        assert not duplicates, f"{environment} has duplicate apt ids: {duplicates}"


def test_every_package_has_an_id_and_category():
    for environment, package_list in aptget.items():
        for package in package_list:
            assert package.get("id"), f"{environment} has a package with no id: {package}"
            assert package.get("category"), f"{environment}: {package['id']} has no category"


def test_the_ubuntu_environments_are_populated():
    # The Windows environments install through winget, not apt.
    for environment in [constants.EnvironmentType.LOCAL_UBUNTU,
                        constants.EnvironmentType.REMOTE_UBUNTU]:
        assert aptget[environment], f"{environment} has no packages"


def test_serverpackages_matches_the_remote_list(bootstrap_dir):
    # serverpackages.txt says to keep this in sync with packages/aptget.py.
    declared = {package["id"] for package in aptget[constants.EnvironmentType.REMOTE_UBUNTU]}
    listed = set(parse_package_text_file(os.path.join(bootstrap_dir, "scripts", "serverpackages.txt")))

    missing_from_text = sorted(declared - listed)
    missing_from_aptget = sorted(listed - declared)

    assert not missing_from_text, \
        f"in aptget REMOTE_UBUNTU but not serverpackages.txt: {missing_from_text}"
    assert not missing_from_aptget, \
        f"in serverpackages.txt but not aptget REMOTE_UBUNTU: {missing_from_aptget}"
