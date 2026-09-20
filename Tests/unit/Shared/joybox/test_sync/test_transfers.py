# Local imports
from joybox import sync
from sync_helpers import (
    REMOTE, REMOTE_TYPE, LOCAL, REMOTE_PATH, positional_arguments, record)


###########################################################
# Transfer operations
#
# Each of these is an rclone command with a source and a destination. Getting
# the two the wrong way round on a sync deletes the side that was correct, and
# rclone reports success for doing it.
###########################################################


###########################################################
# Downloading
###########################################################

def test_a_download_copies_from_the_remote(rclone, monkeypatch, tmp_path):
    recorder = record(monkeypatch)
    sync.download_files_from_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, str(tmp_path))
    arguments = positional_arguments(recorder.only())

    assert arguments[0] == "copy"
    assert arguments[1].startswith(REMOTE + ":")
    assert arguments[2] == str(tmp_path)


def test_a_download_to_a_file_uses_copyto(rclone, monkeypatch, tmp_path):
    # copy would put the file inside a directory of that name.
    recorder = record(monkeypatch)
    sync.download_files_from_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH + "/game.zip", str(tmp_path / "game.zip"))

    assert positional_arguments(recorder.only())[0] == "copyto"


def test_a_download_to_a_trailing_slash_uses_copy(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.download_files_from_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, "/somewhere/new/")

    assert positional_arguments(recorder.only())[0] == "copy"


def test_a_download_carries_the_common_flags(rclone, monkeypatch, tmp_path):
    recorder = record(monkeypatch)
    sync.download_files_from_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, str(tmp_path))

    assert "--transfers" in recorder.only()


def test_a_single_file_download_carries_no_bulk_flags(rclone, monkeypatch, tmp_path):
    # copyto takes one file; the listing and ordering flags do not apply.
    recorder = record(monkeypatch)
    sync.download_files_from_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH + "/game.zip", str(tmp_path / "game.zip"))

    assert "--fast-list" not in recorder.only()


def test_a_download_passes_its_excludes(rclone, monkeypatch, tmp_path):
    recorder = record(monkeypatch)
    sync.download_files_from_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, str(tmp_path), excludes = ["*.tmp"])

    assert recorder.value_after("--exclude") == "*.tmp"


def test_a_download_can_be_limited_to_a_file_list(rclone, monkeypatch, tmp_path):
    listing = tmp_path / "files.txt"
    listing.write_text("game.zip\n")
    recorder = record(monkeypatch)
    sync.download_files_from_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, str(tmp_path), files_from = str(listing))

    assert recorder.value_after("--files-from") == str(listing)


def test_a_missing_file_list_is_not_passed(rclone, monkeypatch, tmp_path):
    # Passing one rclone cannot read would transfer everything instead.
    recorder = record(monkeypatch)
    sync.download_files_from_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, str(tmp_path),
        files_from = str(tmp_path / "absent.txt"))

    assert "--files-from" not in recorder.only()


def test_a_pretend_download_is_a_dry_run(rclone, monkeypatch, tmp_path):
    recorder = record(monkeypatch)
    sync.download_files_from_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, str(tmp_path), pretend_run = True)

    assert "--dry-run" in recorder.only()


def test_a_failed_download_is_reported(rclone, monkeypatch, tmp_path):
    record(monkeypatch, returncode = 1)

    assert sync.download_files_from_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, str(tmp_path)) is False


def test_a_download_without_rclone_is_refused(no_rclone, recording_command, tmp_path):
    assert sync.download_files_from_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, str(tmp_path)) is False
    assert recording_command.ran() is False


###########################################################
# Uploading
###########################################################

def test_an_upload_copies_to_the_remote(rclone, monkeypatch):
    # The reverse of a download: local first, remote second.
    recorder = record(monkeypatch)
    sync.upload_files_to_remote(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)
    arguments = positional_arguments(recorder.calls[0]["cmd"])

    assert arguments[0] == "copy"
    assert arguments[1] == LOCAL
    assert arguments[2].startswith(REMOTE + ":")


def test_an_upload_and_a_download_are_opposites(rclone, monkeypatch, tmp_path):
    recorder = record(monkeypatch)
    sync.upload_files_to_remote(REMOTE, REMOTE_TYPE, REMOTE_PATH, str(tmp_path))
    upload = positional_arguments(recorder.calls[0]["cmd"])
    recorder.calls.clear()
    sync.download_files_from_remote(REMOTE, REMOTE_TYPE, REMOTE_PATH, str(tmp_path))
    download = positional_arguments(recorder.calls[0]["cmd"])

    assert upload[1] == download[2]
    assert upload[2] == download[1]


def test_an_upload_can_skip_existing_files(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.upload_files_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL, skip_existing = True)

    assert "--ignore-existing" in recorder.calls[0]["cmd"]


def test_an_upload_overwrites_by_default(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.upload_files_to_remote(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)

    assert "--ignore-existing" not in recorder.calls[0]["cmd"]


def test_an_upload_passes_its_excludes(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.upload_files_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL, excludes = ["*.tmp", "cache/**"])
    cmd = recorder.calls[0]["cmd"]

    assert cmd.count("--exclude") == 2


def test_a_failed_upload_is_reported(rclone, monkeypatch):
    record(monkeypatch, returncode = 1)

    assert sync.upload_files_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL) is False


def test_a_failed_upload_does_not_update_the_sidecar(rclone, monkeypatch):
    # A sidecar describing files that never arrived is worse than none.
    record(monkeypatch, returncode = 1)

    def fail(**kwargs):
        raise AssertionError("the sidecar should not be written")

    monkeypatch.setattr(sync, "upload_hash_sidecar_files", fail)
    sync.upload_files_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL, local_root = "/locker")


def test_a_successful_upload_updates_the_sidecar(rclone, monkeypatch):
    record(monkeypatch)
    updated = []
    monkeypatch.setattr(
        sync, "upload_hash_sidecar_files",
        lambda **kwargs: updated.append(kwargs) or True)
    sync.upload_files_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL, local_root = "/locker")

    assert updated


def test_the_sidecar_update_can_be_turned_off(rclone, monkeypatch):
    record(monkeypatch)

    def fail(**kwargs):
        raise AssertionError("the sidecar should not be written")

    monkeypatch.setattr(sync, "upload_hash_sidecar_files", fail)
    sync.upload_files_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL,
        local_root = "/locker", update_sidecar = False)


def test_no_local_root_writes_no_sidecar(rclone, monkeypatch):
    record(monkeypatch)

    def fail(**kwargs):
        raise AssertionError("the sidecar should not be written")

    monkeypatch.setattr(sync, "upload_hash_sidecar_files", fail)
    sync.upload_files_to_remote(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)


###########################################################
# Syncing
#
# sync makes the destination match the source, which means deleting whatever
# the source does not have. The direction is the whole safety story.
###########################################################

def test_a_sync_pushes_local_to_remote(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.sync_files_to_remote(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)
    arguments = positional_arguments(recorder.only())

    assert arguments[0] == "sync"
    assert arguments[1] == LOCAL
    assert arguments[2].startswith(REMOTE + ":")


def test_a_sync_never_has_the_remote_as_its_source(rclone, monkeypatch):
    # Reversed, this would delete the local library to match the remote.
    recorder = record(monkeypatch)
    sync.sync_files_to_remote(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)

    assert not positional_arguments(recorder.only())[1].startswith(REMOTE + ":")


def test_a_pretend_sync_is_a_dry_run(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.sync_files_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL, pretend_run = True)

    assert "--dry-run" in recorder.only()


def test_a_failed_sync_is_reported(rclone, monkeypatch):
    record(monkeypatch, returncode = 1)

    assert sync.sync_files_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL) is False


