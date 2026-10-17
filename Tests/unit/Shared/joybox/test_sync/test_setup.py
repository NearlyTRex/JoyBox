# Third-party imports
import pytest

# Local imports
from joybox import sync
from sync_helpers import REMOTE, REMOTE_TYPE, REMOTE_PATH, record


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
