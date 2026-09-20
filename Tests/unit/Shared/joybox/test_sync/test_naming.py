# Third-party imports
import pytest

# Local imports
from joybox import config, sync
from sync_helpers import REMOTE, REMOTE_TYPE


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
# Connection paths
###########################################################

def test_a_remote_path_is_name_colon_path():
    built = sync.get_remote_connection_path(REMOTE, REMOTE_TYPE, "/Gaming")

    assert built.startswith(REMOTE + ":")


def test_a_b2_path_carries_its_bucket():
    # B2 addresses a bucket named after the unencrypted remote.
    built = sync.get_remote_connection_path("hetznerEnc", config.RemoteType.B2, "/Gaming")

    assert built == "hetznerEnc:hetzner/Gaming"


def test_a_non_b2_path_has_no_bucket():
    built = sync.get_remote_connection_path(
        "hetznerEnc", config.RemoteType.DRIVE, "/Gaming")

    assert built == "hetznerEnc:/Gaming"


def test_a_remote_raw_type_is_lowercase():
    assert sync.get_remote_raw_type(REMOTE_TYPE) == \
        sync.get_remote_raw_type(REMOTE_TYPE).lower()


