# Imports
import os

# Local imports
import joybox.bootstrap.installers as installers
from joybox import environment
from fakes import RecordingConnection


###########################################################
# Shared on the venv's path
#
# Scripts import joybox without adjusting sys.path; the venv's joybox.pth is
# what makes that work, so it has to exist and name this checkout's Shared.
###########################################################

SITE_PACKAGES = "/venv/lib/python3.12/site-packages"
PATH_FILE = SITE_PACKAGES + "/joybox.pth"


def build(existing = None, contents = None):
    connection = RecordingConnection(
        existing_paths = existing or [],
        file_contents = contents or {},
        command_output = {"sysconfig": SITE_PACKAGES + "\n"})
    python = installers.Python(connection)
    python.get_packages = lambda: []
    return python, connection


def shared_dir():
    return os.path.join(environment.get_repo_root(expand = True), "Shared")


def test_the_path_file_lives_in_the_venvs_site_packages(isolated_settings):
    python, _ = build()
    assert python.get_path_file() == PATH_FILE


def test_install_writes_the_shared_dir(isolated_settings):
    python, connection = build(existing = ["/venv"])
    python.install()

    assert connection.written_files[PATH_FILE].strip() == shared_dir()


def test_a_missing_path_file_is_not_installed(isolated_settings):
    python, _ = build()
    assert not python.is_installed()


def test_a_path_file_for_another_checkout_is_not_installed(isolated_settings):
    python, _ = build(existing = [PATH_FILE], contents = {PATH_FILE: "/elsewhere/Shared\n"})
    assert not python.is_installed()


def test_a_current_path_file_is_installed(isolated_settings):
    python, _ = build(existing = [PATH_FILE], contents = {PATH_FILE: shared_dir() + "\n"})
    assert python.is_installed()


def test_uninstall_removes_the_path_file(isolated_settings):
    python, connection = build(existing = [PATH_FILE])
    python.uninstall()

    assert PATH_FILE in connection.removed_paths
