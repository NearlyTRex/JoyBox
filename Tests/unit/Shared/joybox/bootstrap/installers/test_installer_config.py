# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Config
#
# JoyBox.ini holds the user's hand edits, so an existing one is never
# overwritten and uninstall keeps a backup.
###########################################################

class UnwritableConnection(RecordingConnection):
    def write_file(self, src, contents, sudo = False):
        self._record("write_file", src, contents, sudo = sudo)
        return False


def make(connection = None):
    connection = connection if connection is not None else RecordingConnection()
    return installers.Config(connection), connection


def test_every_environment_is_supported(isolated_settings):
    config, _ = make()
    assert set(config.get_supported_environments()) == set(constants.EnvironmentType)


def test_installed_follows_the_file(isolated_settings):
    config, connection = make()
    assert not config.is_installed()

    connection.existing_paths.add(config.config_path)
    assert config.is_installed()


def test_the_minimal_template_holds_only_the_minimal_sections(isolated_settings):
    config, _ = make()
    content = config.generate_config_content()

    for section in config.minimal_sections:
        assert f"[{section}]" in content
    assert len(content) < len(config.generate_config_content(full = True))


def test_named_sections_override_the_minimal_set(isolated_settings):
    config, _ = make()
    content = config.generate_config_content(sections = ["Tools.Git"])

    assert "[Tools.Git]" in content
    assert "[UserData.Dirs]" not in content


def test_install_writes_the_minimal_template(isolated_settings):
    config, connection = make()

    assert config.install()
    assert connection.written(config.config_path) == config.generate_config_content()


def test_install_full_writes_every_section(isolated_settings):
    config, connection = make()

    assert config.install_full()
    assert connection.written(config.config_path) == config.generate_config_content(full = True)


def test_an_existing_file_is_never_overwritten(isolated_settings):
    config, connection = make()
    connection.existing_paths.add(config.config_path)

    assert config.install()
    assert config.install_full()
    assert connection.write_log == []


def test_an_unwritable_file_fails_the_install(isolated_settings):
    config, _ = make(UnwritableConnection())

    assert not config.install()
    assert not config.install_full()


def test_uninstall_backs_up_then_removes(isolated_settings):
    config, connection = make()
    connection.existing_paths.add(config.config_path)

    assert config.uninstall()
    assert connection.copied == [(config.config_path, config.config_path + ".backup")]
    assert connection.removed_paths == [config.config_path]


def test_uninstall_of_nothing_succeeds(isolated_settings):
    config, connection = make()

    assert config.uninstall()
    assert connection.copied == []
    assert connection.removed_paths == []
