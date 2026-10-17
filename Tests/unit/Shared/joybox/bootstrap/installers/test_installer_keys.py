# Imports
import os

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Keys
#
# The backup key is the same everywhere and only ever comes from 1Password: a
# key made here would decrypt none of the existing backups. The SSH key is this
# machine's own and is made when missing. Neither is ever overwritten.
###########################################################

RECIPIENT = "age1publicpublicpublicpublicpublicpublicpublicpublicpublicpu"
IDENTITY_LINE = "test-backup-identity-line"


def age_path():
    return os.path.join(os.path.expanduser("~"), ".joybox-age.key")


def ssh_path():
    return os.path.join(os.path.expanduser("~"), ".ssh", "id_ed25519")


@pytest.fixture
def keyring(isolated_settings):
    isolated_settings.set_value("UserData.Backup", "backup_age_identity", age_path())
    isolated_settings.set_value("UserData.Backup", "backup_age_identity_key", IDENTITY_LINE)
    isolated_settings.set_value("UserData.Backup", "backup_age_recipient", RECIPIENT)
    isolated_settings.set_value("UserData.Servers", "server_1_key_filepath", ssh_path())
    return isolated_settings


def make(existing = (), derived = RECIPIENT, **kwargs):
    connection = RecordingConnection(
        existing_paths = list(existing),
        command_output = {"age-keygen -y": derived},
        **kwargs)
    return installers.Keys(connection), connection


def test_only_local_ubuntu_is_supported(keyring):
    keys, _ = make()
    assert keys.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_installed_once_every_key_is_in_place(keyring):
    assert not make()[0].is_installed()
    assert not make(existing = [age_path()])[0].is_installed()
    assert make(existing = [age_path(), ssh_path()])[0].is_installed()


###########################################################
# The backup key
###########################################################

def test_the_backup_key_is_written_owner_only_from_its_setting(keyring):
    keys, connection = make(existing = [ssh_path()])

    assert keys.install()

    assert connection.ran("install -m 600 /dev/null " + age_path())
    assert connection.written(age_path()) == IDENTITY_LINE + "\n"


def test_the_backup_key_is_never_made_here(keyring):
    keys, connection = make(existing = [ssh_path()])
    keyring.set_value("UserData.Backup", "backup_age_identity_key", "")

    assert not keys.install()

    assert connection.written(age_path()) is None
    assert not connection.ran("age-keygen -o")


def test_a_key_that_does_not_match_the_recipient_is_removed(keyring):
    # It would decrypt nothing, and leaving it would make the machine look ready.
    keys, connection = make(existing = [ssh_path()], derived = "age1someoneelse")

    assert not keys.install()

    assert age_path() in connection.removed_paths


def test_a_failed_write_fails_the_install(keyring):
    keys, _ = make(existing = [ssh_path()], return_codes = {"install -m 600": 1})

    assert not keys.install()


###########################################################
# The SSH key
###########################################################

def test_a_missing_ssh_key_is_made_with_its_own_passphrase_prompt(keyring):
    keys, connection = make(existing = [age_path()])

    assert keys.install()

    keygen = [call for call in connection.called("run_interactive") if "ssh-keygen" in call[1][0]]
    assert len(keygen) == 1
    assert keygen[0][1][0][:5] == ["ssh-keygen", "-t", "ed25519", "-f", ssh_path()]
    assert "-N" not in keygen[0][1][0]


def test_a_failed_ssh_keygen_fails_the_install(keyring):
    keys, _ = make(existing = [age_path()], return_codes = {"ssh-keygen": 1})

    assert not keys.install()


def test_existing_keys_are_never_overwritten(keyring):
    keys, connection = make(existing = [age_path(), ssh_path()])

    assert keys.install()

    assert connection.write_log == []
    assert not connection.ran("ssh-keygen")


def test_a_key_without_a_path_is_skipped(keyring):
    keyring.set_value("UserData.Servers", "server_1_key_filepath", "")
    keys, connection = make(existing = [age_path()])

    assert keys.install()
    assert keys.is_installed()

    assert not connection.ran("ssh-keygen")


def test_uninstall_leaves_every_key_in_place(keyring):
    keys, connection = make(existing = [age_path(), ssh_path()])

    assert keys.uninstall()

    assert connection.removed_paths == []
