# Imports
import os

# Local imports
from package_list_helpers import parse_package_text_file


def test_every_listed_manager_exists(bootstrap_dir):
    # install_managers copies each name onto the target and grants it
    # passwordless sudo.
    listed = parse_package_text_file(os.path.join(bootstrap_dir, "scripts", "servermanagers.txt"))
    managers_dir = os.path.join(bootstrap_dir, "managers")
    on_disk = {name for name in os.listdir(managers_dir) if name.endswith(".sh")}

    missing = sorted(set(listed) - on_disk)
    unlisted = sorted(on_disk - set(listed))

    assert not missing, f"servermanagers.txt names scripts that do not exist: {missing}"
    assert not unlisted, f"manager scripts exist but are not listed: {unlisted}"
