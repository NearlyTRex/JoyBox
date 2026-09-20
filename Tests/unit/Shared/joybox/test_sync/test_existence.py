# Third-party imports
import pytest

# Local imports
from joybox import sync
from sync_helpers import REMOTE, REMOTE_TYPE


###########################################################
# Existence checks
###########################################################

def test_a_directory_listing_means_it_exists(rclone, monkeypatch):
    from fakes import RecordingCommand
    recorder = RecordingCommand(monkeypatch, output = "file.zip\nother.zip\n")

    assert sync.does_directory_exist(REMOTE, REMOTE_TYPE, "/Gaming") is True
    assert recorder.only()[:2] == ["/tools/rclone", "lsf"]


@pytest.mark.parametrize("output", [
    "ERROR : something went wrong",
    "error listing: /Gaming",
    "directory not found",
])
def test_an_error_listing_means_it_does_not_exist(rclone, monkeypatch, output):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = output)

    assert sync.does_directory_exist(REMOTE, REMOTE_TYPE, "/Gaming") is False


def test_an_empty_listing_still_means_it_exists(rclone, monkeypatch):
    # An empty directory is not a missing one.
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = "")

    assert sync.does_directory_exist(REMOTE, REMOTE_TYPE, "/Gaming") is True


def test_a_directory_check_without_rclone_is_false(no_rclone, recording_command):
    assert sync.does_directory_exist(REMOTE, REMOTE_TYPE, "/Gaming") is False


def test_a_file_exists_when_lsjson_succeeds(rclone, monkeypatch):
    from fakes import RecordingCommand
    recorder = RecordingCommand(monkeypatch, returncode = 0)

    assert sync.does_file_exist(REMOTE, REMOTE_TYPE, "/Gaming/game.zip") is True
    assert recorder.only()[:2] == ["/tools/rclone", "lsjson"]


def test_a_file_does_not_exist_when_lsjson_fails(rclone, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert sync.does_file_exist(REMOTE, REMOTE_TYPE, "/Gaming/game.zip") is False


def test_a_file_check_suppresses_its_output(rclone, monkeypatch):
    # Otherwise a missing file logs an error for what is a normal question.
    from fakes import RecordingCommand
    recorder = RecordingCommand(monkeypatch, returncode = 1)
    sync.does_file_exist(REMOTE, REMOTE_TYPE, "/Gaming/game.zip")

    assert recorder.options().is_output_suppressed() is True


def test_a_path_exists_if_it_is_a_file(rclone, monkeypatch):
    monkeypatch.setattr(sync, "does_file_exist", lambda **kwargs: True)

    def fail(**kwargs):
        raise AssertionError("the directory check should not be needed")

    monkeypatch.setattr(sync, "does_directory_exist", fail)

    assert sync.does_path_exist(REMOTE, REMOTE_TYPE, "/Gaming/game.zip") is True


def test_a_path_falls_back_to_the_directory_check(rclone, monkeypatch):
    monkeypatch.setattr(sync, "does_file_exist", lambda **kwargs: False)
    monkeypatch.setattr(sync, "does_directory_exist", lambda **kwargs: True)

    assert sync.does_path_exist(REMOTE, REMOTE_TYPE, "/Gaming") is True


def test_a_path_that_is_neither_does_not_exist(rclone, monkeypatch):
    monkeypatch.setattr(sync, "does_file_exist", lambda **kwargs: False)
    monkeypatch.setattr(sync, "does_directory_exist", lambda **kwargs: False)

    assert sync.does_path_exist(REMOTE, REMOTE_TYPE, "/absent") is False


###########################################################
# Checksums
###########################################################

def test_a_remote_md5_is_read(rclone, monkeypatch):
    from fakes import RecordingCommand
    recorder = RecordingCommand(
        monkeypatch, output = "d41d8cd98f00b204e9800998ecf8427e  game.zip\n")
    built = sync.get_path_md5(REMOTE, REMOTE_TYPE, "/Gaming/game.zip")

    assert "md5sum" in recorder.text()
    assert built


def test_a_matching_md5_is_recognised(rclone, monkeypatch):
    monkeypatch.setattr(
        sync, "get_path_md5",
        lambda **kwargs: "D41D8CD98F00B204E9800998ECF8427E")

    assert sync.does_path_match_md5(
        REMOTE, REMOTE_TYPE, "/Gaming/game.zip",
        "d41d8cd98f00b204e9800998ecf8427e") is True


def test_md5_comparison_ignores_case(rclone, monkeypatch):
    # rclone reports lowercase; sidecars may hold either.
    monkeypatch.setattr(
        sync, "get_path_md5", lambda **kwargs: "abcdef0123456789")

    assert sync.does_path_match_md5(
        REMOTE, REMOTE_TYPE, "/x", "ABCDEF0123456789") is True


def test_a_differing_md5_is_rejected(rclone, monkeypatch):
    monkeypatch.setattr(sync, "get_path_md5", lambda **kwargs: "aaaa")

    assert sync.does_path_match_md5(REMOTE, REMOTE_TYPE, "/x", "bbbb") is False


def test_an_unavailable_md5_is_not_a_match(rclone, monkeypatch):
    monkeypatch.setattr(sync, "get_path_md5", lambda **kwargs: None)

    assert sync.does_path_match_md5(REMOTE, REMOTE_TYPE, "/x", "bbbb") is False


###########################################################
# Hash database paths
###########################################################

def test_a_hash_database_path_uses_forward_slashes():
    # Remote paths are posix regardless of the host.
    built = sync.get_hash_database_path("Gaming\\Roms")

    assert "\\" not in built


def test_a_hash_database_path_is_under_the_remote_path():
    assert sync.get_hash_database_path("Gaming").startswith("Gaming/")


def test_a_hash_database_path_works_without_a_remote_path():
    assert sync.get_hash_database_path()


