# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# 1Password
#
# The desktop app and the op CLI come from the same repository; both are
# needed, since the CLI is how settings resolve op:// references.
###########################################################

def make():
    connection = RecordingConnection()
    return installers.OnePassword(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    onepassword, _ = make()
    assert onepassword.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_the_app_alone_is_not_installed(isolated_settings):
    onepassword, connection = make()
    connection.existing_paths.add(onepassword.app_path)
    assert not onepassword.is_installed()

    connection.existing_paths.add(onepassword.cli_path)
    assert onepassword.is_installed()


def test_install_sets_up_the_debsig_policy_and_the_signed_repository(isolated_settings):
    onepassword, connection = make()

    assert onepassword.install()
    assert connection.made_directories == [onepassword.policy_path, onepassword.policy_keyring_path]
    assert connection.ran("--dearmor -o", onepassword.archive_key_path)
    assert connection.ran("--dearmor -o", f"{onepassword.policy_keyring_path}/debsig.gpg")
    assert f"signed-by={onepassword.archive_key_path}" in connection.written(onepassword.sources_list_path)
    assert connection.ran("install -y 1password 1password-cli")


def test_uninstall_removes_the_packages_the_repository_and_the_policy(isolated_settings):
    onepassword, connection = make()

    assert onepassword.uninstall()
    assert connection.ran("remove -y 1password 1password-cli")
    assert connection.removed_paths == [
        onepassword.sources_list_path, onepassword.archive_key_path,
        onepassword.policy_path, onepassword.policy_keyring_path]
