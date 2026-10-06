# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# GitKraken
###########################################################

def make():
    connection = RecordingConnection()
    return installers.GitKraken(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    gitkraken, _ = make()
    assert gitkraken.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_installed_follows_the_binary(isolated_settings):
    gitkraken, connection = make()
    assert not gitkraken.is_installed()

    connection.existing_paths.add("/usr/bin/gitkraken")
    assert gitkraken.is_installed()


def test_install_installs_the_downloaded_package_and_cleans_up(isolated_settings):
    gitkraken, connection = make()

    assert gitkraken.install()
    assert connection.downloads == [(gitkraken.download_url, gitkraken.deb_path)]
    assert connection.ran("install -y", gitkraken.deb_path)
    assert connection.removed_paths == [gitkraken.deb_path]


def test_uninstall_removes_the_package(isolated_settings):
    gitkraken, connection = make()

    assert gitkraken.uninstall()
    assert connection.ran("remove -y gitkraken")
