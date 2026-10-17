# Imports
import os

# Local imports
import joybox.bootstrap.constants as constants
from joybox.bootstrap.packages.aptget import aptget
from package_list_helpers import parse_package_text_file


def test_no_duplicate_ids():
    duplicates = {
        environment: sorted({package["id"] for package in package_list
                             if [other["id"] for other in package_list].count(package["id"]) > 1})
        for environment, package_list in aptget.items()}

    assert not any(duplicates.values()), f"duplicate apt ids: {duplicates}"


def test_every_package_has_an_id_and_category():
    incomplete = [
        (environment, package) for environment, package_list in aptget.items() for package in package_list
        if not package.get("id") or not package.get("category")]

    assert not incomplete, f"packages without an id or category: {incomplete}"


def test_the_ubuntu_environments_are_populated():
    # The Windows environments install through winget, not apt.
    empty = [environment for environment in [constants.EnvironmentType.LOCAL_UBUNTU,
                                             constants.EnvironmentType.REMOTE_UBUNTU] if not aptget[environment]]

    assert not empty, f"environments with no packages: {empty}"


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
