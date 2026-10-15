# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_udev
from fakes import RecordingConnection


###########################################################
# Udev
###########################################################

RULE = installer_udev.UDEV_RULES[0]
RULE_PATH = f"/etc/udev/rules.d/{RULE['filename']}"
RULE_PATHS = [f"/etc/udev/rules.d/{rule['filename']}" for rule in installer_udev.UDEV_RULES]


class UnwritableConnection(RecordingConnection):
    def write_file(self, src, contents, sudo = False):
        self._record("write_file", src, contents, sudo = sudo)
        return False


def make(connection = None):
    connection = connection if connection is not None else RecordingConnection()
    return installers.Udev(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    udev, _ = make()
    assert udev.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_installed_needs_every_rule(isolated_settings):
    udev, connection = make()
    assert not udev.is_installed()

    connection.existing_paths.add(RULE_PATH)
    assert not udev.is_installed()

    connection.existing_paths.update(RULE_PATHS)
    assert udev.is_installed()


def test_install_writes_each_rule_and_reloads(isolated_settings):
    udev, connection = make()

    assert udev.install()
    for rule, path in zip(installer_udev.UDEV_RULES, RULE_PATHS, strict = True):
        assert connection.written(path) == rule["content"] + "\n"
    assert connection.ran("udevadm control --reload-rules")
    assert connection.ran("udevadm trigger")


def test_an_existing_rule_is_left_alone(isolated_settings):
    udev, connection = make()
    connection.existing_paths.update(RULE_PATHS)

    assert udev.install()
    assert connection.write_log == []


def test_an_unwritable_rule_fails_the_install(isolated_settings):
    udev, connection = make(UnwritableConnection())

    assert not udev.install()
    assert not connection.ran("udevadm")


def test_a_failed_reload_fails_the_install(isolated_settings):
    udev, connection = make(RecordingConnection(return_codes = {"--reload-rules": 1}))

    assert not udev.install()
    assert not connection.ran("udevadm trigger")


def test_a_failed_trigger_fails_the_install(isolated_settings):
    udev, _ = make(RecordingConnection(return_codes = {"udevadm trigger": 1}))
    assert not udev.install()


def test_uninstall_removes_present_rules_and_reloads(isolated_settings):
    udev, connection = make()
    connection.existing_paths.update(RULE_PATHS)
    assert udev.uninstall()
    assert connection.removed_paths == RULE_PATHS
    assert connection.ran("udevadm trigger")

    udev, connection = make()
    assert udev.uninstall()
    assert connection.removed_paths == []


def test_onboard_bluetooth_rule_deauthorizes_on_add_and_trigger():
    rule = next(r for r in installer_udev.UDEV_RULES if "bluetooth" in r["filename"])
    assert 'ACTION!="remove"' in rule["content"]
    assert 'ATTR{idVendor}=="0489", ATTR{idProduct}=="e14f"' in rule["content"]
    assert rule["content"].endswith('ATTR{authorized}="0"')
