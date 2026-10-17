# Imports
import os

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# VSCodium
#
# The settings and extensions kept in the repo are what every machine's editor
# gets; backup captures this machine's into the repo for review.
###########################################################

SETTINGS = '{\n    "files.trimTrailingWhitespace": true\n}\n'
PROGRAM = "/usr/bin/codium"


@pytest.fixture
def captured(tmp_path, monkeypatch):
    # The repo's Bootstrap/vscodium, in a scratch directory
    directory = tmp_path / "vscodium"
    directory.mkdir()
    (directory / "settings.json").write_text(SETTINGS)
    (directory / "extensions.txt").write_text("# kept\neamodio.gitlens\n\n")
    monkeypatch.setattr(installers.installer_vscodium.bootstrap, "get_data_dir", lambda: str(tmp_path))
    return directory


def make(existing = (), file_contents = None, extensions = "", **kwargs):
    connection = RecordingConnection(
        existing_paths = list(existing),
        file_contents = file_contents or {},
        command_output = {"--list-extensions": extensions},
        **kwargs)
    return installers.VSCodium(connection), connection


def user_path(name):
    return os.path.join(os.path.expanduser("~"), ".config", "VSCodium", "User", name)


def test_only_local_ubuntu_is_supported(isolated_settings, captured):
    vscodium, _ = make()
    assert vscodium.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


###########################################################
# Installed
###########################################################

def test_without_the_program_nothing_is_installed(isolated_settings, captured):
    vscodium, _ = make()
    assert not vscodium.is_installed()


def test_installed_once_the_settings_and_extensions_match(isolated_settings, captured):
    vscodium, _ = make(existing = [PROGRAM, user_path("settings.json")],
        file_contents = {user_path("settings.json"): SETTINGS}, extensions = "Eamodio.GitLens\n")
    assert vscodium.is_installed()


def test_settings_that_differ_are_not_installed(isolated_settings, captured):
    vscodium, _ = make(existing = [PROGRAM, user_path("settings.json")],
        file_contents = {user_path("settings.json"): "{}"}, extensions = "eamodio.gitlens\n")
    assert not vscodium.is_installed()


def test_a_missing_extension_is_not_installed(isolated_settings, captured):
    vscodium, _ = make(existing = [PROGRAM, user_path("settings.json")],
        file_contents = {user_path("settings.json"): SETTINGS})
    assert not vscodium.is_installed()


###########################################################
# Installing
###########################################################

def test_install_dearmors_the_key_and_adds_the_signed_repository(isolated_settings, captured):
    vscodium, connection = make()

    assert vscodium.install()
    assert connection.ran("--dearmor -o", vscodium.archive_key_path, "/tmp/vscodium.gpg")
    assert "/tmp/vscodium.gpg" in connection.removed_paths
    assert connection.written(vscodium.sources_list) == (
        f"deb [signed-by={vscodium.archive_key_path}] {vscodium.repo_url} vscodium main\n")
    assert connection.moved == [(f"/tmp/{vscodium.sources_list}", vscodium.sources_list_path)]
    assert connection.ran("install -y codium")


def test_an_installed_program_is_not_installed_again(isolated_settings, captured):
    vscodium, connection = make(existing = [PROGRAM])

    assert vscodium.install()
    assert not connection.ran("install -y codium")


def test_the_settings_and_extensions_are_deployed(isolated_settings, captured):
    vscodium, connection = make(existing = [PROGRAM])

    assert vscodium.install()
    assert connection.written(user_path("settings.json")) == SETTINGS
    assert connection.ran(PROGRAM, "--install-extension", "eamodio.gitlens")


def test_replaced_settings_are_kept_once(isolated_settings, captured):
    vscodium, connection = make(existing = [PROGRAM, user_path("settings.json")],
        file_contents = {user_path("settings.json"): "{}"}, extensions = "eamodio.gitlens\n")

    assert vscodium.install()
    assert connection.copied[0][:2] == (user_path("settings.json"), user_path("settings.json") + ".joybox.backup")


def test_an_existing_backup_is_never_overwritten(isolated_settings, captured):
    backup = user_path("settings.json") + ".joybox.backup"
    vscodium, connection = make(existing = [PROGRAM, user_path("settings.json"), backup],
        file_contents = {user_path("settings.json"): "{}"}, extensions = "eamodio.gitlens\n")

    assert vscodium.install()
    assert connection.copied == []


def test_matching_settings_and_extensions_are_left_alone(isolated_settings, captured):
    vscodium, connection = make(existing = [PROGRAM, user_path("settings.json")],
        file_contents = {user_path("settings.json"): SETTINGS}, extensions = "eamodio.gitlens\n")

    assert vscodium.install()
    assert connection.write_log == []
    assert not connection.ran("--install-extension")


def test_a_failed_settings_write_fails_the_install(isolated_settings, captured):
    class UnwritableConnection(RecordingConnection):
        def write_file(self, src, contents, sudo = False):
            return False

    connection = UnwritableConnection(existing_paths = [PROGRAM])
    assert not installers.VSCodium(connection).install()


def test_a_failed_extension_fails_the_install(isolated_settings, captured):
    vscodium, _ = make(existing = [PROGRAM], return_codes = {"--install-extension": 1})
    assert not vscodium.install()


###########################################################
# Capturing
###########################################################

def test_backup_captures_the_settings_and_extensions(isolated_settings, captured):
    vscodium, connection = make(existing = [user_path("settings.json")],
        file_contents = {user_path("settings.json"): SETTINGS}, extensions = "b.second\na.first\n")

    assert vscodium.backup()
    assert connection.written(str(captured / "settings.json")) == SETTINGS
    assert connection.written(str(captured / "extensions.txt")) == "a.first\nb.second\n"
    assert connection.written(str(captured / "keybindings.json")) is None


def test_a_failed_capture_fails_the_backup(isolated_settings, captured):
    class UnwritableConnection(RecordingConnection):
        def write_file(self, src, contents, sudo = False):
            return False

    connection = UnwritableConnection(existing_paths = [user_path("settings.json")],
        file_contents = {user_path("settings.json"): SETTINGS})
    assert not installers.VSCodium(connection).backup()


def test_a_failed_extensions_capture_fails_the_backup(isolated_settings, captured):
    class SettingsOnlyConnection(RecordingConnection):
        def write_file(self, src, contents, sudo = False):
            return not src.endswith("extensions.txt")

    assert not installers.VSCodium(SettingsOnlyConnection()).backup()


def test_uninstall_removes_the_package_and_the_repository(isolated_settings, captured):
    vscodium, connection = make()

    assert vscodium.uninstall()
    assert connection.ran("remove -y codium")
    assert connection.removed_paths == [vscodium.sources_list_path, vscodium.archive_key_path]
