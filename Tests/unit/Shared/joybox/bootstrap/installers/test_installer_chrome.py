# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Chrome
#
# The .deb registers its own repository, so install only fetches and installs
# it; uninstall removes what the package left behind.
###########################################################

def make():
    connection = RecordingConnection()
    return installers.Chrome(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    chrome, _ = make()
    assert chrome.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_installed_follows_the_browser_binary(isolated_settings):
    chrome, connection = make()
    assert not chrome.is_installed()

    connection.existing_paths.add("/usr/bin/google-chrome")
    assert chrome.is_installed()


def test_install_installs_the_downloaded_package_and_cleans_up(isolated_settings):
    chrome, connection = make()

    assert chrome.install()
    assert connection.downloads[0][1] == "/tmp/google-chrome.deb"
    assert connection.ran(chrome.aptgetinstall_tool, "-i", "/tmp/google-chrome.deb")
    assert connection.removed_paths == ["/tmp/google-chrome.deb"]


def test_uninstall_removes_the_package_and_the_repository(isolated_settings):
    chrome, connection = make()

    assert chrome.uninstall()
    assert connection.ran("remove -y google-chrome-stable")
    assert connection.removed_paths == [chrome.sources_list_path, chrome.archive_key_path]
