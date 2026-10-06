# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Brave
###########################################################

def make():
    connection = RecordingConnection()
    return installers.Brave(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    brave, _ = make()
    assert brave.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_installed_follows_the_browser_binary(isolated_settings):
    brave, connection = make()
    assert not brave.is_installed()

    connection.existing_paths.add("/usr/bin/brave-browser")
    assert brave.is_installed()


def test_install_adds_the_signed_repository_then_the_package(isolated_settings):
    brave, connection = make()

    assert brave.install()
    assert connection.downloads == [(f"{brave.url}/{brave.archive_key}", brave.archive_key_path)]
    assert connection.written(brave.sources_list).startswith(f"deb [signed-by={brave.archive_key_path}] {brave.url}/")
    assert connection.moved == [(f"/tmp/{brave.sources_list}", brave.sources_list_path)]
    assert connection.ran("install -y brave-browser")


def test_uninstall_removes_the_package_and_the_repository(isolated_settings):
    brave, connection = make()

    assert brave.uninstall()
    assert connection.ran("remove -y brave-browser")
    assert connection.removed_paths == [brave.sources_list_path, brave.archive_key_path]
