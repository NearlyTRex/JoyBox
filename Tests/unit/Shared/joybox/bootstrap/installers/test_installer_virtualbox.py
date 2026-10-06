# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_virtualbox
from fakes import RecordingConnection


###########################################################
# VirtualBox
#
# The Oracle repository is per release; the Ubuntu codename is used so Mint
# and other derivatives get the matching suite.
###########################################################

CODENAME = "noble"
VBOX_BINARY = "/usr/bin/virtualbox"


def make(monkeypatch):
    monkeypatch.setattr(installer_virtualbox.platform_info, "get_ubuntu_codename", lambda: CODENAME)
    connection = RecordingConnection()
    return installers.VirtualBox(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings, monkeypatch):
    virtualbox, _ = make(monkeypatch)
    assert virtualbox.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_status_follows_the_binary(isolated_settings, monkeypatch):
    virtualbox, connection = make(monkeypatch)
    assert not virtualbox.is_installed()
    assert virtualbox.get_package_status() == {"installed": [], "missing": [virtualbox.package_name]}

    connection.existing_paths.add(VBOX_BINARY)
    assert virtualbox.is_installed()
    assert virtualbox.get_package_status() == {"installed": [virtualbox.package_name], "missing": []}


def test_install_adds_the_release_repository_then_the_package(isolated_settings, monkeypatch):
    virtualbox, connection = make(monkeypatch)
    connection.existing_paths.add(VBOX_BINARY)

    assert virtualbox.install()
    assert connection.ran("--output", virtualbox.archive_key_path, "--dearmor")
    assert "/tmp/oracle_vbox_2016.asc" in connection.removed_paths
    assert connection.written(virtualbox.sources_list).endswith(f"{virtualbox.url} {CODENAME} contrib\n")
    assert connection.moved == [(f"/tmp/{virtualbox.sources_list}", virtualbox.sources_list_path)]
    assert connection.ran("install -y", virtualbox.package_name)


def test_install_fails_when_no_binary_appears(isolated_settings, monkeypatch):
    virtualbox, _ = make(monkeypatch)
    assert not virtualbox.install()


def test_uninstall_removes_the_package_and_the_repository(isolated_settings, monkeypatch):
    virtualbox, connection = make(monkeypatch)

    assert virtualbox.uninstall()
    assert connection.ran("remove -y", virtualbox.package_name)
    assert connection.removed_paths == [virtualbox.sources_list_path, virtualbox.archive_key_path]
