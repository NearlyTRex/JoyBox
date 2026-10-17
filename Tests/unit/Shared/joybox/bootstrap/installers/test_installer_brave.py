# Third-party imports
import pytest

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


def test_install_takes_braves_keyring_and_source_then_the_package(isolated_settings):
    brave, connection = make()

    assert brave.install()
    assert connection.downloads == [
        (f"{brave.url}/brave-browser-archive-keyring.gpg", "/usr/share/keyrings/brave-browser-archive-keyring.gpg"),
        (f"{brave.url}/brave-browser.sources", "/etc/apt/sources.list.d/brave-browser-release.sources")]
    assert connection.ran("update")
    assert connection.ran("install -y brave-browser")


def test_install_drops_the_one_line_source_earlier_installs_wrote(isolated_settings):
    brave, connection = make()
    connection.existing_paths.add("/etc/apt/sources.list.d/brave-browser-release.list")

    assert brave.install()
    assert connection.removed_paths == ["/etc/apt/sources.list.d/brave-browser-release.list"]


@pytest.mark.parametrize("failing", ["brave-browser-archive-keyring.gpg", "brave-browser.sources"])
def test_a_failed_download_stops_before_apt_runs(isolated_settings, monkeypatch, failing):
    brave, connection = make()
    monkeypatch.setattr(connection, "download_file", lambda url, dest, sudo = False: not url.endswith(failing))

    assert brave.install() is False
    assert not connection.ran("update")
    assert not connection.ran("install -y brave-browser")


def test_uninstall_removes_the_package_and_the_repository(isolated_settings):
    brave, connection = make()

    assert brave.uninstall()
    assert connection.ran("remove -y brave-browser")
    assert connection.removed_paths == [
        "/etc/apt/sources.list.d/brave-browser-release.sources",
        "/etc/apt/sources.list.d/brave-browser-release.list",
        "/usr/share/keyrings/brave-browser-archive-keyring.gpg"]
