# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_sysctl
from fakes import RecordingConnection


###########################################################
# Sysctl
#
# One drop-in file owned by JoyBox; installed means its contents match exactly.
###########################################################

class UnwritableConnection(RecordingConnection):
    def write_file(self, src, contents, sudo = False):
        self._record("write_file", src, contents, sudo = sudo)
        return False


def make(connection = None):
    connection = connection if connection is not None else RecordingConnection()
    return installers.Sysctl(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    sysctl, _ = make()
    assert sysctl.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_the_drop_in_lists_every_setting():
    contents = installers.Sysctl(RecordingConnection())._build_contents()

    assert contents.startswith("# Managed by JoyBox")
    for setting in installer_sysctl.SYSCTL_SETTINGS:
        assert f"{setting['key']} = {setting['value']}\n" in contents


def test_installed_needs_the_exact_contents(isolated_settings):
    sysctl, connection = make()
    assert not sysctl.is_installed()

    connection.existing_paths.add(sysctl.conf_path)
    connection.file_contents[sysctl.conf_path] = "fs.inotify.max_user_instances = 128\n"
    assert not sysctl.is_installed()

    connection.file_contents[sysctl.conf_path] = sysctl._build_contents()
    assert sysctl.is_installed()


def test_install_writes_and_applies(isolated_settings):
    sysctl, connection = make()

    assert sysctl.install()
    assert connection.written(sysctl.conf_path) == sysctl._build_contents()
    assert connection.ran("sysctl --system")


def test_an_unwritable_drop_in_fails_the_install(isolated_settings):
    sysctl, connection = make(UnwritableConnection())

    assert not sysctl.install()
    assert not connection.ran("sysctl")


def test_a_failed_apply_fails_the_install(isolated_settings):
    sysctl, _ = make(RecordingConnection(return_codes = {"sysctl --system": 1}))
    assert not sysctl.install()


def test_uninstall_removes_and_reloads(isolated_settings):
    sysctl, connection = make()
    connection.existing_paths.add(sysctl.conf_path)

    assert sysctl.uninstall()
    assert connection.removed_paths == [sysctl.conf_path]
    assert connection.ran("sysctl --system")


def test_uninstall_of_nothing_runs_nothing(isolated_settings):
    sysctl, connection = make()

    assert sysctl.uninstall()
    assert connection.commands == []
