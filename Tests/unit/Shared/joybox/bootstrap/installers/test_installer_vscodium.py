# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# VSCodium
###########################################################

def make():
    connection = RecordingConnection()
    return installers.VSCodium(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    vscodium, _ = make()
    assert vscodium.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_installed_follows_the_binary(isolated_settings):
    vscodium, connection = make()
    assert not vscodium.is_installed()

    connection.existing_paths.add("/usr/bin/codium")
    assert vscodium.is_installed()


def test_install_dearmors_the_key_and_adds_the_signed_repository(isolated_settings):
    vscodium, connection = make()

    assert vscodium.install()
    assert connection.ran("--dearmor -o", vscodium.archive_key_path, "/tmp/vscodium.gpg")
    assert "/tmp/vscodium.gpg" in connection.removed_paths
    assert connection.written(vscodium.sources_list) == (
        f"deb [signed-by={vscodium.archive_key_path}] {vscodium.repo_url} vscodium main\n")
    assert connection.moved == [(f"/tmp/{vscodium.sources_list}", vscodium.sources_list_path)]
    assert connection.ran("install -y codium")


def test_uninstall_removes_the_package_and_the_repository(isolated_settings):
    vscodium, connection = make()

    assert vscodium.uninstall()
    assert connection.ran("remove -y codium")
    assert connection.removed_paths == [vscodium.sources_list_path, vscodium.archive_key_path]
