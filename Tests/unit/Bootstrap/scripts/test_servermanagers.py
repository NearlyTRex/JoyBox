# Imports
import os

# Third-party imports
import pytest


def parse_package_text_file(path):
    entries = []
    with open(path, "r") as package_file:
        for line in package_file:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line)
    return entries


def test_every_listed_manager_exists(bootstrap_dir):

    # install_managers copies each name in this list onto the target and grants
    # it passwordless sudo. A name with no file fails partway through a provision.
    listed = parse_package_text_file(os.path.join(bootstrap_dir, "scripts", "servermanagers.txt"))
    managers_dir = os.path.join(bootstrap_dir, "managers")
    on_disk = {name for name in os.listdir(managers_dir) if name.endswith(".sh")}

    missing = sorted(set(listed) - on_disk)
    unlisted = sorted(on_disk - set(listed))

    assert not missing, f"servermanagers.txt names scripts that do not exist: {missing}"
    assert not unlisted, f"manager scripts exist but are not listed: {unlisted}"
