# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_zram
from fakes import RecordingConnection


###########################################################
# Zram
#
# The generator package plus one config file owned by JoyBox; installed means
# the generator is present and the config matches exactly.
###########################################################

class UnwritableConnection(RecordingConnection):
    def write_file(self, src, contents, sudo = False):
        self._record("write_file", src, contents, sudo = sudo)
        return False


def make(connection = None):
    connection = connection if connection is not None else RecordingConnection()
    return installers.Zram(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    zram, _ = make()
    assert zram.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_the_config_lists_every_setting_under_the_device(isolated_settings):
    zram, _ = make()
    contents = zram.get_contents()

    assert contents.startswith("# Managed by JoyBox")
    assert "[zram0]\n" in contents
    for setting in installer_zram.ZRAM_SETTINGS:
        assert f"{setting['key']} = {setting['value']}\n" in contents


def test_installed_needs_the_generator_and_the_exact_config(isolated_settings):
    zram, connection = make()
    connection.existing_paths.add(zram.generator_path)
    assert not zram.is_installed()

    connection.existing_paths.discard(zram.generator_path)
    connection.existing_paths.add(zram.conf_path)
    connection.file_contents[zram.conf_path] = zram.get_contents()
    assert not zram.is_installed()

    connection.existing_paths.add(zram.generator_path)
    assert zram.is_installed()

    connection.file_contents[zram.conf_path] = "[zram0]\nzram-size = ram / 4\n"
    assert not zram.is_installed()


def test_install_adds_the_package_writes_and_starts(isolated_settings):
    zram, connection = make()

    assert zram.install()
    assert connection.ran("install", "systemd-zram-generator")
    assert connection.written(zram.conf_path) == zram.get_contents()
    assert connection.ran("systemctl daemon-reload")
    assert connection.ran("systemctl start systemd-zram-setup@zram0")


def test_a_failed_package_install_writes_nothing(isolated_settings):
    zram, connection = make(RecordingConnection(return_codes = {"systemd-zram-generator": 1}))

    assert not zram.install()
    assert connection.written(zram.conf_path) is None


def test_an_unwritable_config_fails_before_starting(isolated_settings):
    zram, connection = make(UnwritableConnection())

    assert not zram.install()
    assert not connection.ran("systemctl")


def test_a_failed_reload_fails_before_starting(isolated_settings):
    zram, connection = make(RecordingConnection(return_codes = {"daemon-reload": 1}))

    assert not zram.install()
    assert not connection.ran("systemctl start")


def test_a_failed_start_fails_the_install(isolated_settings):
    zram, _ = make(RecordingConnection(return_codes = {"systemctl start": 1}))
    assert not zram.install()


def test_uninstall_stops_and_removes(isolated_settings):
    zram, connection = make()
    connection.existing_paths.add(zram.conf_path)

    assert zram.uninstall()
    assert connection.ran("systemctl stop systemd-zram-setup@zram0")
    assert connection.removed_paths == [zram.conf_path]
    assert connection.ran("remove", "systemd-zram-generator")


def test_uninstall_without_a_config_removes_nothing(isolated_settings):
    zram, connection = make()

    assert zram.uninstall()
    assert connection.removed_paths == []
    assert connection.ran("remove", "systemd-zram-generator")
