# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer
from joybox.bootstrap.installers import installer_winget
from fakes import RecordingConnection


###########################################################
# WinGet
###########################################################

PACKAGES = ["Git.Git", "7zip.7zip"]


# The Windows tool settings are only defaulted on Windows
def on_windows(isolated_settings, monkeypatch):
    monkeypatch.setattr(installer.platform_info, "is_windows_platform", lambda: True)
    isolated_settings.set_value("Tools.WinGet", "winget_exe", "winget.exe")
    isolated_settings.set_value("Tools.WinGet", "winget_install_dir", "C:/WindowsApps")


def make(isolated_settings, monkeypatch, packages = PACKAGES, **kwargs):
    on_windows(isolated_settings, monkeypatch)
    connection = RecordingConnection(**kwargs)
    winget = installers.WinGet(connection)
    winget.get_packages = lambda: list(packages)
    return winget, connection


def test_only_local_windows_is_supported(isolated_settings, monkeypatch):
    winget, _ = make(isolated_settings, monkeypatch)
    assert winget.get_supported_environments() == [constants.EnvironmentType.LOCAL_WINDOWS]


def test_the_package_list_follows_the_environment_type(isolated_settings, monkeypatch):
    on_windows(isolated_settings, monkeypatch)
    winget = installers.WinGet(RecordingConnection())
    winget.set_environment_type(constants.EnvironmentType.LOCAL_WINDOWS)

    assert winget.get_packages() == installer_winget.packages.winget[constants.EnvironmentType.LOCAL_WINDOWS]


def test_installed_needs_every_package(isolated_settings, monkeypatch):
    winget, connection = make(isolated_settings, monkeypatch)
    assert winget.is_installed()
    assert connection.ran(winget.winget_tool, "list --name Git.Git")

    winget, _ = make(isolated_settings, monkeypatch, return_codes = {"--name 7zip.7zip": 1})
    assert not winget.is_installed()


def test_package_status_splits_installed_and_missing(isolated_settings, monkeypatch):
    winget, _ = make(isolated_settings, monkeypatch, return_codes = {"--name Git.Git": 1})
    assert winget.get_package_status() == {"installed": ["7zip.7zip"], "missing": ["Git.Git"]}


def test_install_accepts_agreements_and_matches_ids_exactly(isolated_settings, monkeypatch):
    winget, connection = make(isolated_settings, monkeypatch)

    assert winget.install()
    assert connection.ran("install --accept-package-agreements --accept-source-agreements --id Git.Git -e -h")


def test_a_failed_install_stops(isolated_settings, monkeypatch):
    winget, connection = make(isolated_settings, monkeypatch, return_codes = {"install --accept-package-agreements --accept-source-agreements --id Git.Git": 1})

    assert not winget.install()
    assert not connection.ran("--id 7zip.7zip")


def test_uninstall_removes_every_package(isolated_settings, monkeypatch):
    winget, connection = make(isolated_settings, monkeypatch)

    assert winget.uninstall()
    assert connection.ran("uninstall --id Git.Git -e -h")
    assert connection.ran("uninstall --id 7zip.7zip -e -h")


def test_a_failed_uninstall_stops(isolated_settings, monkeypatch):
    winget, connection = make(isolated_settings, monkeypatch, return_codes = {"uninstall --id Git.Git": 1})

    assert not winget.uninstall()
    assert not connection.ran("uninstall --id 7zip.7zip")
