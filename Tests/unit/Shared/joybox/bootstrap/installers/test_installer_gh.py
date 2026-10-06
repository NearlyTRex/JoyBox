# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# GitHub CLI
###########################################################

GH_BINARY = "/usr/bin/gh"


def make():
    connection = RecordingConnection()
    return installers.Gh(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    gh, _ = make()
    assert gh.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_status_follows_the_binary(isolated_settings):
    gh, connection = make()
    assert not gh.is_installed()
    assert gh.get_package_status() == {"installed": [], "missing": ["gh"]}

    connection.existing_paths.add(GH_BINARY)
    assert gh.is_installed()
    assert gh.get_package_status() == {"installed": ["gh"], "missing": []}


def test_install_adds_the_signed_repository_then_the_package(isolated_settings):
    gh, connection = make()
    connection.existing_paths.add(GH_BINARY)

    assert gh.install()
    assert connection.downloads == [(f"{gh.url}/{gh.archive_key}", gh.archive_key_path)]
    assert f"signed-by={gh.archive_key_path}" in connection.written(gh.sources_list)
    assert connection.moved == [(f"/tmp/{gh.sources_list}", gh.sources_list_path)]
    assert connection.ran("install -y gh")


def test_install_fails_when_no_binary_appears(isolated_settings):
    gh, _ = make()
    assert not gh.install()


def test_uninstall_removes_the_package_and_the_repository(isolated_settings):
    gh, connection = make()

    assert gh.uninstall()
    assert connection.ran("remove -y gh")
    assert connection.removed_paths == [gh.sources_list_path, gh.archive_key_path]
