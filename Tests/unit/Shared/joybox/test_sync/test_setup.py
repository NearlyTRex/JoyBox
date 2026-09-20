# Third-party imports
import pytest

# Local imports
from joybox import config, sync
from sync_helpers import REMOTE, REMOTE_TYPE, REMOTE_PATH, record


###########################################################
# Configuring a remote
#
# Every transfer afterwards addresses the remote by the name written here, so
# a remote created under the wrong name or type is one that no later command
# can reach.
###########################################################

def test_a_manual_remote_is_created_under_its_name(rclone, recording_command):
    sync.setup_manual_remote(REMOTE, REMOTE_TYPE)
    cmd = recording_command.only()

    assert cmd[:3] == ["/tools/rclone", "config", "create"]
    assert cmd[3] == REMOTE


def test_a_remote_is_created_as_the_type_rclone_knows(rclone, recording_command):
    # rclone takes its own lowercase backend names, not the collection's.
    sync.setup_manual_remote(REMOTE, config.RemoteType.SFTP)

    assert recording_command.only()[4] == "sftp"


def test_configuration_values_are_passed_as_pairs(rclone, recording_command):
    sync.setup_manual_remote(
        REMOTE, REMOTE_TYPE,
        remote_config = {"host": "example.test", "user": "deploy"})
    cmd = recording_command.only()

    assert "host=example.test" in cmd
    assert "user=deploy" in cmd


def test_no_configuration_adds_no_pairs(rclone, recording_command):
    sync.setup_manual_remote(REMOTE, REMOTE_TYPE)

    assert recording_command.only() == \
        ["/tools/rclone", "config", "create", REMOTE, sync.get_remote_raw_type(REMOTE_TYPE)]


def test_a_failed_creation_reports_failure(rclone, monkeypatch):
    record(monkeypatch, returncode = 1)

    assert sync.setup_manual_remote(REMOTE, REMOTE_TYPE) is False


def test_creating_a_remote_without_rclone_reports_failure(no_rclone, recording_command):
    assert sync.setup_manual_remote(REMOTE, REMOTE_TYPE) is False
    assert recording_command.ran() is False


###########################################################
# Remotes that authorize themselves
###########################################################

def test_an_autoconnect_remote_is_created_then_authorized(rclone, recording_command):
    # The create only writes the stanza; the reconnect is what opens the
    # browser and stores the token.
    assert sync.setup_autoconnect_remote(REMOTE, config.RemoteType.DRIVE) is True

    assert recording_command.calls[0]["cmd"][:3] == ["/tools/rclone", "config", "create"]
    assert recording_command.calls[1]["cmd"][2:] == ["reconnect", "%s:" % REMOTE]


def test_an_autoconnect_remote_is_not_treated_as_local(rclone, recording_command):
    # Without this rclone tries to open a browser on the machine holding the
    # config rather than handing over a url.
    sync.setup_autoconnect_remote(REMOTE, config.RemoteType.DRIVE)

    assert "config_is_local=false" in recording_command.calls[0]["cmd"]


def test_a_remote_that_will_not_be_created_is_not_authorized(rclone, monkeypatch):
    recorder = record(monkeypatch, returncode = 1)

    assert sync.setup_autoconnect_remote(REMOTE, config.RemoteType.DRIVE) is False
    assert len(recorder.calls) == 1


def test_an_autoconnect_remote_without_rclone_reports_failure(no_rclone, recording_command):
    assert sync.setup_autoconnect_remote(REMOTE, config.RemoteType.DRIVE) is False
    assert recording_command.ran() is False


###########################################################
# Choosing how to configure
###########################################################

@pytest.fixture
def routes(monkeypatch):
    calls = []
    for name in ["setup_autoconnect_remote", "setup_manual_remote"]:
        monkeypatch.setattr(
            sync, name,
            (lambda name: lambda **kwargs: calls.append((name, kwargs)) or True)(name))
    return calls


def test_a_drive_remote_authorizes_itself(routes):
    sync.setup_remote(REMOTE, config.RemoteType.DRIVE)

    assert routes[0][0] == "setup_autoconnect_remote"


@pytest.mark.parametrize("remote_type", [
    config.RemoteType.B2,
    config.RemoteType.SFTP,
    config.RemoteType.WEBDAV,
])
def test_every_other_remote_is_configured_manually(routes, remote_type):
    sync.setup_remote(REMOTE, remote_type)

    assert routes[0][0] == "setup_manual_remote"


def test_a_configuration_given_as_json_is_parsed(routes):
    # The config comes out of the ini file as one string.
    sync.setup_remote(
        REMOTE, config.RemoteType.SFTP,
        remote_config = '{"host": "example.test", "port": "22"}')

    assert routes[0][1]["remote_config"] == {"host": "example.test", "port": "22"}


def test_a_configuration_given_as_a_mapping_is_passed_through(routes):
    sync.setup_remote(
        REMOTE, config.RemoteType.SFTP, remote_config = {"host": "example.test"})

    assert routes[0][1]["remote_config"] == {"host": "example.test"}


###########################################################
# Encrypted remotes
###########################################################

def test_an_encrypted_remote_wraps_the_plain_one(rclone, recording_command):
    sync.setup_encrypted_remote(REMOTE, REMOTE_PATH, "passphrase")
    cmd = recording_command.only()

    assert cmd[3] == sync.get_encrypted_remote_name(REMOTE)
    assert cmd[4] == "crypt"
    assert "remote=%s:" % REMOTE in cmd


def test_an_encrypted_remote_is_named_once(rclone, recording_command):
    # Wrapping an already wrapped name would create hetznerEncEnc.
    sync.setup_encrypted_remote(sync.get_encrypted_remote_name(REMOTE), REMOTE_PATH, "key")

    assert recording_command.only()[3] == "%sEnc" % REMOTE


def test_an_encrypted_remote_without_rclone_reports_failure(no_rclone, recording_command):
    assert sync.setup_encrypted_remote(REMOTE, REMOTE_PATH, "key") is False
    assert recording_command.ran() is False


def test_a_failed_encrypted_remote_reports_failure(rclone, monkeypatch):
    record(monkeypatch, returncode = 1)

    assert sync.setup_encrypted_remote(REMOTE, REMOTE_PATH, "key") is False


###########################################################
# Remote checksums
###########################################################

MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def test_a_checksum_is_read_from_the_remote(rclone, monkeypatch):
    record(monkeypatch, output = "%s  Game.zip\n" % MD5)

    assert sync.get_path_md5(REMOTE, REMOTE_TYPE, REMOTE_PATH) == MD5


def test_a_checksum_command_addresses_the_remote_path(rclone, recording_command):
    sync.get_path_md5(REMOTE, REMOTE_TYPE, REMOTE_PATH)
    cmd = recording_command.only()

    assert cmd[1] == "md5sum"
    assert cmd[2] == sync.get_remote_connection_path(REMOTE, REMOTE_TYPE, REMOTE_PATH)


def test_byte_output_is_decoded_for_a_checksum(rclone, monkeypatch):
    record(monkeypatch, output = ("%s  Game.zip\n" % MD5).encode())

    assert sync.get_path_md5(REMOTE, REMOTE_TYPE, REMOTE_PATH) == MD5


@pytest.mark.parametrize("output", [
    "file does not exist",
    "error reading remote",
    "",
    "no separator here",
])
def test_an_unusable_checksum_response_yields_nothing(rclone, monkeypatch, output):
    record(monkeypatch, output = output)

    assert sync.get_path_md5(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None


def test_a_checksum_without_rclone_yields_nothing(no_rclone, recording_command):
    assert sync.get_path_md5(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None
    assert recording_command.ran() is False


def test_a_matching_checksum_is_recognised(rclone, monkeypatch):
    record(monkeypatch, output = "%s  Game.zip\n" % MD5)

    assert sync.does_path_match_md5(REMOTE, REMOTE_TYPE, REMOTE_PATH, MD5) is True


def test_a_checksum_comparison_ignores_case(rclone, monkeypatch):
    # rclone prints lowercase; the collection stores some hashes uppercase.
    record(monkeypatch, output = "%s  Game.zip\n" % MD5)

    assert sync.does_path_match_md5(REMOTE, REMOTE_TYPE, REMOTE_PATH, MD5.upper()) is True


def test_a_differing_checksum_is_not_a_match(rclone, monkeypatch):
    record(monkeypatch, output = "%s  Game.zip\n" % MD5)

    assert sync.does_path_match_md5(REMOTE, REMOTE_TYPE, REMOTE_PATH, "0" * 32) is False


def test_a_missing_remote_file_never_matches(rclone, monkeypatch):
    record(monkeypatch, output = "file does not exist")

    assert sync.does_path_match_md5(REMOTE, REMOTE_TYPE, REMOTE_PATH, MD5) is False


###########################################################
# Remote modification times
###########################################################

def test_a_modification_time_is_read_from_the_remote(rclone, monkeypatch):
    record(monkeypatch, output = "  1024 2024-01-02 03:04:05.000000000 Game.zip\n")

    assert sync.get_path_mod_time(REMOTE, REMOTE_TYPE, REMOTE_PATH) > 0


def test_a_modification_time_command_lists_with_details(rclone, recording_command):
    sync.get_path_mod_time(REMOTE, REMOTE_TYPE, REMOTE_PATH)

    assert recording_command.only()[1] == "lsl"


def test_two_different_times_do_not_read_as_equal(rclone, monkeypatch):
    record(monkeypatch, output = "  1024 2024-01-02 03:04:05.000000000 Game.zip\n")
    first = sync.get_path_mod_time(REMOTE, REMOTE_TYPE, REMOTE_PATH)
    record(monkeypatch, output = "  1024 2025-06-07 08:09:10.000000000 Game.zip\n")
    second = sync.get_path_mod_time(REMOTE, REMOTE_TYPE, REMOTE_PATH)

    assert second > first


@pytest.mark.parametrize("output", [
    "error reading remote",
    "directory not found",
    "",
    "  1024 Game.zip",
])
def test_an_unusable_time_response_is_nothing(rclone, monkeypatch, output):
    record(monkeypatch, output = output)

    assert sync.get_path_mod_time(REMOTE, REMOTE_TYPE, REMOTE_PATH) == 0


def test_a_modification_time_without_rclone_is_nothing(no_rclone, recording_command):
    assert sync.get_path_mod_time(REMOTE, REMOTE_TYPE, REMOTE_PATH) == 0
    assert recording_command.ran() is False
