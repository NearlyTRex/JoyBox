# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_xorg
from fakes import RecordingConnection


###########################################################
# Xorg
###########################################################

class UnwritableConnection(RecordingConnection):
    def write_file(self, src, contents, sudo = False):
        self._record("write_file", src, contents, sudo = sudo)
        return False


def make(connection = None):
    connection = connection if connection is not None else RecordingConnection()
    return installers.Xorg(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    xorg, _ = make()
    assert xorg.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_each_input_class_is_a_complete_section(isolated_settings):
    xorg, _ = make()
    contents = xorg.build_contents()

    for input_class in installer_xorg.INPUT_CLASSES:
        assert f'Section "InputClass"\n    Identifier "{input_class["identifier"]}"\n' in contents
        for option in input_class["options"]:
            assert f"    {option}\n" in contents
    assert contents.count("Section ") == contents.count("EndSection")


def test_installed_needs_the_exact_contents(isolated_settings):
    xorg, connection = make()
    assert not xorg.is_installed()

    connection.existing_paths.add(xorg.conf_path)
    assert not xorg.is_installed()

    connection.file_contents[xorg.conf_path] = xorg.build_contents()
    assert xorg.is_installed()


def test_install_creates_the_directory_and_writes(isolated_settings):
    xorg, connection = make()

    assert xorg.install()
    assert connection.ran("install -d -m 0755 /etc/X11/xorg.conf.d")
    assert connection.written(xorg.conf_path) == xorg.build_contents()


def test_a_failed_directory_fails_the_install(isolated_settings):
    xorg, connection = make(RecordingConnection(return_codes = {"install -d": 1}))

    assert not xorg.install()
    assert connection.write_log == []


def test_an_unwritable_drop_in_fails_the_install(isolated_settings):
    xorg, _ = make(UnwritableConnection())
    assert not xorg.install()


def test_uninstall_removes_a_present_drop_in(isolated_settings):
    xorg, connection = make()
    connection.existing_paths.add(xorg.conf_path)
    assert xorg.uninstall()
    assert connection.removed_paths == [xorg.conf_path]

    xorg, connection = make()
    assert xorg.uninstall()
    assert connection.removed_paths == []
