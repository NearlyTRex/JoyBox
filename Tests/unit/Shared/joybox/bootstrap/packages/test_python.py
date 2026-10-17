# Imports
import os
import re

# Local imports
from joybox.bootstrap.packages.python import python as python_packages


def test_no_duplicate_ids():
    # LOCAL_WINDOWS extends LOCAL_UBUNTU, so one duplicate shows up twice.
    duplicates = {
        environment: sorted({package["id"] for package in package_list
                             if [other["id"] for other in package_list].count(package["id"]) > 1})
        for environment, package_list in python_packages.items()}

    assert not any(duplicates.values()), f"duplicate python ids: {duplicates}"


def test_every_package_has_an_id_and_category():
    incomplete = [
        (environment, package) for environment, package_list in python_packages.items() for package in package_list
        if not package.get("id") or not package.get("category")]

    assert not incomplete, f"packages without an id or category: {incomplete}"


def test_paramiko_is_declared(repo_root):
    # ConnectionSSH imports it lazily, so a missing declaration surfaces partway through a deploy.
    with open(os.path.join(repo_root, "requirements.in"), "r", encoding = "utf-8") as requirements:
        names = {re.split(r"[<>=!~;\[ ]", line.split("#")[0].strip())[0].lower() for line in requirements}

    assert "paramiko" in names
