# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_flatpak
from fakes import RecordingConnection

ENVIRONMENT = constants.EnvironmentType.LOCAL_UBUNTU
PACKAGES = [
    {"id": "org.example.Named", "name": "Named", "repository": "custom"},
    {"id": "org.example.Bare"},
    {"name": "org.example.Legacy"},
]


@pytest.fixture
def flatpak_packages(isolated_settings, monkeypatch):
    isolated_settings.set_value("UserData.General", "environment_type", ENVIRONMENT)
    monkeypatch.setitem(installer_flatpak.packages.flatpak, ENVIRONMENT, list(PACKAGES))
    return PACKAGES


def build(**kwargs):
    connection = RecordingConnection(**kwargs)
    return installers.Flatpak(connection), connection


###########################################################
# Package descriptors
###########################################################

def test_package_id_prefers_id_then_name():
    assert installer_flatpak.get_flatpak_package_id({"id": "a", "name": "b"}) == "a"
    assert installer_flatpak.get_flatpak_package_id({"name": "b"}) == "b"
    assert installer_flatpak.get_flatpak_package_id({}) == ""


def test_package_info_defaults():
    assert installer_flatpak.get_flatpak_package_info({"id": "org.example.Bare"}) == {
        "id": "org.example.Bare",
        "repository": "flathub",
        "name": "org.example.Bare",
        "description": "",
        "category": "",
    }


def test_package_info_uses_the_display_name_only_alongside_an_id():
    assert installer_flatpak.get_flatpak_package_info(PACKAGES[0])["name"] == "Named"
    assert installer_flatpak.get_flatpak_package_info(PACKAGES[2])["name"] == "org.example.Legacy"


###########################################################
# Status
###########################################################

def test_supports_local_and_remote_ubuntu(isolated_settings):
    flatpak, _ = build()
    assert flatpak.get_supported_environments() == [
        constants.EnvironmentType.LOCAL_UBUNTU,
        constants.EnvironmentType.REMOTE_UBUNTU,
    ]


def test_unknown_environment_has_no_packages(isolated_settings):
    isolated_settings.set_value("UserData.General", "environment_type", "Nowhere")
    flatpak, _ = build()
    assert flatpak.get_packages() == []
    assert flatpak.is_installed()


def test_status_queries_each_package_by_id(flatpak_packages):
    flatpak, connection = build(return_codes = {"info --user org.example.Bare": 1})
    assert flatpak.get_package_status() == {
        "installed": ["Named", "org.example.Legacy"],
        "missing": ["org.example.Bare"],
    }
    assert connection.ran("info --user org.example.Named")
    assert not flatpak.is_installed()


def test_installed_when_every_package_is_present(flatpak_packages):
    flatpak, _ = build()
    assert flatpak.is_installed()


###########################################################
# Install and uninstall
###########################################################

def test_install_adds_flathub_then_each_package_from_its_repository(flatpak_packages):
    flatpak, connection = build()
    assert flatpak.install()
    strings = connection.command_strings()
    assert "remote-add --user --if-not-exists flathub" in strings[0]
    assert connection.ran("install --user -y custom org.example.Named")
    assert connection.ran("install --user -y flathub org.example.Bare")
    assert connection.ran("install --user -y flathub org.example.Legacy")


def test_install_stops_when_flathub_cannot_be_added(flatpak_packages):
    flatpak, connection = build(return_codes = {"remote-add": 1})
    assert not flatpak.install()
    assert not connection.ran("install --user")


def test_install_stops_at_the_first_failing_package(flatpak_packages):
    flatpak, connection = build(return_codes = {"org.example.Bare": 1})
    assert not flatpak.install()
    assert not connection.ran("org.example.Legacy")


def test_uninstall_removes_each_package(flatpak_packages):
    flatpak, connection = build()
    assert flatpak.uninstall()
    for pkg_id in ("org.example.Named", "org.example.Bare", "org.example.Legacy"):
        assert connection.ran(f"uninstall --user -y {pkg_id}")


def test_uninstall_stops_at_the_first_failing_package(flatpak_packages):
    flatpak, connection = build(return_codes = {"org.example.Named": 1})
    assert not flatpak.uninstall()
    assert not connection.ran("org.example.Bare")


def test_update_packages_reports_the_exit_code(isolated_settings):
    flatpak, connection = build()
    assert flatpak.update_packages()
    assert connection.ran("update --user -y")
    flatpak, _ = build(return_codes = {"update --user": 1})
    assert not flatpak.update_packages()
