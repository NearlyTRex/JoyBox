# Imports
import pytest

# Local imports
from joybox import config, sync


###########################################################
# Remote naming
#
# An encrypted remote is the plain one with an "Enc" suffix, and rclone is
# invoked with whichever name the caller derived - so a mismatch reads from
# the wrong remote entirely.
###########################################################

def test_an_encrypted_name_gains_the_suffix():
    assert sync.get_encrypted_remote_name("Hetzner") == "HetznerEnc"


def test_an_already_encrypted_name_is_unchanged():
    assert sync.get_encrypted_remote_name("HetznerEnc") == "HetznerEnc"


def test_an_unencrypted_name_loses_the_suffix():
    assert sync.get_unencrypted_remote_name("HetznerEnc") == "Hetzner"


def test_an_already_unencrypted_name_is_unchanged():
    assert sync.get_unencrypted_remote_name("Hetzner") == "Hetzner"


@pytest.mark.parametrize("name", ["Hetzner", "B2", "Drive"])
def test_the_pair_round_trips(name):
    assert sync.get_unencrypted_remote_name(sync.get_encrypted_remote_name(name)) == name


@pytest.mark.parametrize("name", ["Hetzner", "HetznerEnc"])
def test_both_directions_are_idempotent(name):
    encrypted = sync.get_encrypted_remote_name(name)
    unencrypted = sync.get_unencrypted_remote_name(name)

    assert sync.get_encrypted_remote_name(encrypted) == encrypted
    assert sync.get_unencrypted_remote_name(unencrypted) == unencrypted


def test_a_name_containing_enc_is_not_stripped_mid_name():
    # Only a trailing suffix counts, or "Encrypted" would become "rypted".
    assert sync.get_unencrypted_remote_name("Encrypted") == "Encrypted"


###########################################################
# Connection paths
###########################################################

def test_a_standard_remote_path_is_name_and_path():
    assert sync.get_remote_connection_path("Hetzner", config.RemoteType.SFTP, "/data") == \
        "Hetzner:/data"


def test_a_b2_remote_path_inserts_the_bucket():
    # B2 addresses a bucket named after the unencrypted remote.
    built = sync.get_remote_connection_path("MyRemoteEnc", config.RemoteType.B2, "/data")

    assert built == "MyRemoteEnc:MyRemote/data"


def test_a_b2_bucket_uses_the_unencrypted_name():
    built = sync.get_remote_connection_path("MyRemoteEnc", config.RemoteType.B2, "/data")

    assert "MyRemote/" in built


###########################################################
# Flags
###########################################################

def base_flags():
    return sync.get_common_remote_flags("Remote", config.RemoteType.SFTP, None)


def test_the_common_flags_are_always_present():
    flags = base_flags()

    for flag in ["--fast-list", "--tpslimit", "--transfers", "--order-by"]:
        assert flag in flags


def test_transfers_are_serialized():
    # Concurrent transfers to the storage box have caused throttling.
    flags = base_flags()

    assert flags[flags.index("--transfers") + 1] == "1"


@pytest.mark.parametrize("action_type", config.RemoteActionSyncType.members())
def test_a_sync_action_tracks_renames(action_type):
    flags = sync.get_common_remote_flags("Remote", config.RemoteType.SFTP, action_type)

    assert "--track-renames" in flags


@pytest.mark.parametrize("action_type", config.RemoteActionChangeType.members())
def test_a_change_action_creates_empty_directories(action_type):
    flags = sync.get_common_remote_flags("Remote", config.RemoteType.SFTP, action_type)

    assert "--create-empty-src-dirs" in flags


def test_a_drive_remote_gets_its_own_flags():
    flags = sync.get_common_remote_flags("Remote", config.RemoteType.DRIVE, None)

    for flag in ["--drive-acknowledge-abuse", "--drive-stop-on-upload-limit",
                 "--drive-stop-on-download-limit", "--drive-chunk-size"]:
        assert flag in flags


def test_a_non_drive_remote_gets_no_drive_flags():
    flags = sync.get_common_remote_flags("Remote", config.RemoteType.SFTP, None)

    assert not any(flag.startswith("--drive-") for flag in flags)


###########################################################
# Excludes
###########################################################

def test_each_exclude_becomes_a_flag_pair():
    assert sync.get_exclude_flags(["one", "two"]) == \
        ["--exclude", "one", "--exclude", "two"]


def test_a_single_exclude_string_is_accepted():
    assert sync.get_exclude_flags("one") == ["--exclude", "one"]


def test_empty_excludes_produce_no_flags():
    assert sync.get_exclude_flags([]) == []
    assert sync.get_exclude_flags("") == []
    assert sync.get_exclude_flags(None) == []


def test_blank_entries_are_skipped():
    # A bare "--exclude" with no pattern would consume the next argument.
    assert sync.get_exclude_flags(["one", "", "two"]) == \
        ["--exclude", "one", "--exclude", "two"]


def test_exclude_flags_stay_paired():
    flags = sync.get_exclude_flags(["a", "b", "c"])

    assert len(flags) % 2 == 0
    assert flags[::2] == ["--exclude"] * 3
