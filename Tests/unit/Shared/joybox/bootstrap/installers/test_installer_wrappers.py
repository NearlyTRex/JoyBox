# Imports
import os

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Wrappers
#
# Only python3 and pip3 are wrapped now; pip installs the JoyBox commands into
# the venv. A machine set up before that still has a wrapper per script, which
# would shadow the installed commands, so they are removed.
###########################################################

def build(recorded = None):
    connection = RecordingConnection()
    wrappers = installers.Wrappers(connection)
    connection.existing_paths.add(wrappers.venv_python)
    if recorded is not None:
        connection.existing_paths.add(wrappers.marker_path)
        connection.file_contents[wrappers.marker_path] = "\n".join(recorded)
    return wrappers, connection


def test_install_writes_only_the_python_wrappers(isolated_settings):
    wrappers, connection = build()
    assert wrappers.install()

    written = sorted(os.path.basename(path) for path in connection.written_files
                     if path != wrappers.marker_path)
    assert written == ["pip3", "python3"]


def test_old_script_wrappers_are_removed(isolated_settings):
    wrappers, connection = build(recorded = ["backup_tool", "verify_server", "python3", "pip3"])
    assert wrappers.install()

    removed = sorted(os.path.basename(path) for path in connection.removed_paths)
    assert removed == ["backup_tool", "verify_server"]


def test_a_marker_listing_script_wrappers_is_not_installed(isolated_settings):
    wrappers, _ = build(recorded = ["backup_tool", "python3", "pip3"])
    assert not wrappers.is_installed()


def test_the_python_wrappers_alone_are_installed(isolated_settings):
    wrappers, _ = build(recorded = ["python3", "pip3"])
    assert wrappers.is_installed()


def test_install_needs_the_venv(isolated_settings):
    connection = RecordingConnection()
    assert not installers.Wrappers(connection).install()


def test_only_local_ubuntu_is_supported(isolated_settings):
    wrappers, _ = build()
    assert wrappers.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_an_unwritable_wrapper_fails_the_install(isolated_settings, monkeypatch):
    wrappers, connection = build()
    monkeypatch.setattr(connection, "write_file", lambda src, contents, sudo = False: False)

    assert not wrappers.install()
    assert connection.permissions == []


def test_uninstall_removes_the_recorded_wrappers_and_the_marker(isolated_settings):
    wrappers, connection = build(recorded = ["python3", "pip3"])

    assert wrappers.uninstall()
    assert sorted(os.path.basename(path) for path in connection.removed_paths) == sorted(
        ["python3", "pip3", os.path.basename(wrappers.marker_path)])


def test_package_status_follows_the_marker(isolated_settings):
    wrappers, _ = build(recorded = ["python3"])
    assert wrappers.get_package_status() == {"installed": ["python3"], "missing": ["pip3"]}
