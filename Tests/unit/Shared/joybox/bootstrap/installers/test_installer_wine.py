# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_wine
from fakes import RecordingConnection


###########################################################
# Wine
#
# WineHQ publishes one sources file per Ubuntu release, so the codename picks
# both the file and its name on disk.
###########################################################

CODENAME = "noble"


def make(monkeypatch):
    monkeypatch.setattr(installer_wine.platform_info, "get_ubuntu_codename", lambda: CODENAME)
    connection = RecordingConnection()
    return installers.Wine(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings, monkeypatch):
    wine, _ = make(monkeypatch)
    assert wine.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_installed_follows_the_binary(isolated_settings, monkeypatch):
    wine, connection = make(monkeypatch)
    assert not wine.is_installed()

    connection.existing_paths.add("/usr/bin/wine")
    assert wine.is_installed()


def test_install_enables_i386_and_uses_the_release_sources(isolated_settings, monkeypatch):
    wine, connection = make(monkeypatch)

    assert wine.install()
    assert connection.ran(wine.aptgetinstall_tool, "--add-architecture i386")
    assert (f"{wine.url}/ubuntu/dists/{CODENAME}/winehq-{CODENAME}.sources",
        f"/etc/apt/sources.list.d/winehq-{CODENAME}.sources") in connection.downloads
    assert connection.ran("install -y winehq-devel")
    assert connection.ran("install -y winetricks")


def test_uninstall_removes_the_packages_and_the_repository(isolated_settings, monkeypatch):
    wine, connection = make(monkeypatch)

    assert wine.uninstall()
    assert connection.ran("remove -y winehq-devel")
    assert connection.ran("remove -y winetricks")
    assert connection.removed_paths == [wine.sources_list_path, wine.archive_key_path]
