# Imports
import os

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Autostart
#
# Each machine starts only its own role at login: the host streams, the
# living-room client connects.
###########################################################

def entry_path(filename):
    return os.path.join(os.path.expanduser("~"), ".config", "autostart", filename)


def sunshine_path():
    return entry_path("joybox-sunshine.desktop")


def moonlight_path():
    return entry_path("joybox-moonlight.desktop")


class UnwritableConnection(RecordingConnection):
    def write_file(self, src, contents, sudo = False):
        self._record("write_file", src, contents, sudo = sudo)
        return False


def make(isolated_settings, sunshine = False, moonlight = False, connection = None):
    isolated_settings.set_value("Tools.Sunshine", "sunshine_streaming_host", str(sunshine))
    isolated_settings.set_value("Tools.Moonlight", "moonlight_autostart", str(moonlight))
    connection = connection if connection is not None else RecordingConnection()
    return installers.Autostart(connection), connection


def exec_line(contents):
    return next(line for line in contents.splitlines() if line.startswith("Exec="))[len("Exec="):]


def test_only_local_ubuntu_is_supported(isolated_settings):
    autostart, _ = make(isolated_settings)
    assert autostart.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_a_streaming_host_starts_sunshine(isolated_settings):
    autostart, connection = make(isolated_settings, sunshine = True)

    assert autostart.install()

    assert exec_line(connection.written(sunshine_path())).endswith(os.path.join("bin", "launch_sunshine"))
    assert connection.written(moonlight_path()) is None


def test_a_client_starts_moonlight(isolated_settings):
    autostart, connection = make(isolated_settings, moonlight = True)

    assert autostart.install()

    assert exec_line(connection.written(moonlight_path())).endswith(os.path.join("bin", "launch_moonlight"))
    assert connection.written(sunshine_path()) is None


def test_an_entry_turned_off_is_removed(isolated_settings):
    autostart, connection = make(isolated_settings,
        connection = RecordingConnection(existing_paths = [sunshine_path()]))

    assert autostart.install()

    assert sunshine_path() in connection.removed_paths


def test_installed_when_the_entries_match_the_settings(isolated_settings):
    autostart, _ = make(isolated_settings, sunshine = True)
    assert not autostart.is_installed()

    autostart, _ = make(isolated_settings, sunshine = True,
        connection = RecordingConnection(existing_paths = [sunshine_path()]))
    assert autostart.is_installed()

    autostart, _ = make(isolated_settings,
        connection = RecordingConnection(existing_paths = [sunshine_path()]))
    assert not autostart.is_installed()


def test_a_failed_write_fails_the_install(isolated_settings):
    autostart, _ = make(isolated_settings, sunshine = True, connection = UnwritableConnection())

    assert not autostart.install()


def test_uninstall_removes_every_entry(isolated_settings):
    autostart, connection = make(isolated_settings,
        connection = RecordingConnection(existing_paths = [sunshine_path(), moonlight_path()]))

    assert autostart.uninstall()

    assert connection.removed_paths == [sunshine_path(), moonlight_path()]


def test_uninstall_skips_entries_that_are_already_gone(isolated_settings):
    autostart, connection = make(isolated_settings,
        connection = RecordingConnection(existing_paths = [moonlight_path()]))

    assert autostart.uninstall()

    assert connection.removed_paths == [moonlight_path()]
