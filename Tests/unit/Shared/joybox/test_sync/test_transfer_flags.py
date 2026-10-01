# Third-party imports
import pytest

# Local imports
from joybox import sync
from sync_helpers import REMOTE, REMOTE_TYPE, LOCAL, REMOTE_PATH, positional_arguments, record


###########################################################
# Run flags on every transfer
#
# Each wrapper builds its own command, so each has its own chance to drop a
# flag the caller asked for. One table drives them all.
###########################################################

TRANSFERS = {
    "download_files_from_remote": dict(
        remote_name = REMOTE, remote_type = REMOTE_TYPE, remote_path = REMOTE_PATH,
        local_path = "/somewhere/new/"),
    "upload_files_to_remote": dict(
        remote_name = REMOTE, remote_type = REMOTE_TYPE, remote_path = REMOTE_PATH,
        local_path = LOCAL),
    "sync_files_to_remote": dict(
        remote_name = REMOTE, remote_type = REMOTE_TYPE, remote_path = REMOTE_PATH,
        local_path = LOCAL),
    "move_files_on_remote": dict(
        remote_name = REMOTE, remote_type = REMOTE_TYPE, src_path = "/Gaming/Old",
        dest_path = "/Gaming/New"),
    "purge_path_on_remote": dict(
        remote_name = REMOTE, remote_type = REMOTE_TYPE, remote_path = "/Gaming/Old"),
    "delete_file_on_remote": dict(
        remote_name = REMOTE, remote_type = REMOTE_TYPE, remote_path = "/Gaming/game.zip"),
    "pull_files_from_remote": dict(
        remote_name = REMOTE, remote_type = REMOTE_TYPE, remote_path = REMOTE_PATH,
        local_path = LOCAL),
    "push_files_to_remote": dict(
        remote_name = REMOTE, remote_type = REMOTE_TYPE, remote_path = REMOTE_PATH,
        local_path = LOCAL),
    "merge_files_both_ways": dict(
        remote_name = REMOTE, remote_type = REMOTE_TYPE, remote_path = REMOTE_PATH,
        local_path = LOCAL),
    "copy_remote_to_remote": dict(
        src_remote_name = REMOTE, src_remote_type = REMOTE_TYPE, src_remote_path = REMOTE_PATH,
        dest_remote_name = "backblaze", dest_remote_type = REMOTE_TYPE,
        dest_remote_path = "/Backup"),
}

INTERACTIVE = [
    "download_files_from_remote", "upload_files_to_remote",
    "pull_files_from_remote", "push_files_to_remote", "merge_files_both_ways",
]


def run(name, **extra):
    kwargs = dict(TRANSFERS[name])
    kwargs.update(extra)
    return getattr(sync, name)(**kwargs)


@pytest.mark.parametrize("name", sorted(TRANSFERS))
def test_a_verbose_transfer_asks_rclone_to_be_verbose(rclone, recording_command, name):
    run(name, verbose = True)

    assert "--verbose" in recording_command.calls[0]["cmd"]


@pytest.mark.parametrize("name", sorted(TRANSFERS))
def test_a_quiet_transfer_is_not_verbose(rclone, recording_command, name):
    run(name)

    assert "--verbose" not in recording_command.calls[0]["cmd"]


@pytest.mark.parametrize("name", sorted(TRANSFERS))
def test_a_pretend_transfer_is_a_dry_run(rclone, recording_command, name):
    run(name, pretend_run = True)

    assert "--dry-run" in recording_command.calls[0]["cmd"]
    assert recording_command.calls[0]["kwargs"]["pretend_run"] is True


@pytest.mark.parametrize("name", sorted(TRANSFERS))
def test_a_transfer_hands_on_exit_on_failure(rclone, recording_command, name):
    run(name, exit_on_failure = True)

    assert recording_command.calls[0]["kwargs"]["exit_on_failure"] is True


@pytest.mark.parametrize("name", INTERACTIVE)
def test_an_interactive_transfer_asks_before_acting(rclone, recording_command, name):
    run(name, interactive = True)

    assert "--interactive" in recording_command.calls[0]["cmd"]


@pytest.mark.parametrize("name", INTERACTIVE)
def test_a_transfer_is_not_interactive_unasked(rclone, recording_command, name):
    run(name)

    assert "--interactive" not in recording_command.calls[0]["cmd"]


@pytest.mark.parametrize("name", sorted(TRANSFERS))
def test_a_failed_transfer_reports_failure(rclone, monkeypatch, name):
    record(monkeypatch, returncode = 1)

    assert run(name) is False


@pytest.mark.parametrize("name", sorted(TRANSFERS))
def test_a_transfer_without_rclone_is_refused(no_rclone, quiet, recording_command, name):
    assert run(name) is False
    assert recording_command.ran() is False


###########################################################
# One-way sync
###########################################################

def test_a_sync_to_the_remote_puts_local_first(rclone, recording_command):
    assert run("sync_files_to_remote") is True
    arguments = positional_arguments(recording_command.only())

    assert arguments[0] == "sync"
    assert arguments[1] == LOCAL
    assert arguments[2] == sync.get_remote_connection_path(REMOTE, REMOTE_TYPE, REMOTE_PATH)


###########################################################
# File lists
###########################################################

@pytest.fixture
def file_list(tmp_path):
    listing = tmp_path / "files.txt"
    listing.write_text("game.zip\n")
    return str(listing)


def test_an_upload_can_be_limited_to_a_file_list(rclone, recording_command, file_list):
    run("upload_files_to_remote", files_from = file_list)

    assert recording_command.value_after("--files-from") == file_list


def test_an_upload_with_an_unreadable_file_list_is_refused(rclone, quiet, recording_command, tmp_path):
    assert run("upload_files_to_remote", files_from = str(tmp_path / "absent.txt")) is False
    assert recording_command.ran() is False


###########################################################
# Sidecar after upload
###########################################################

def test_a_failed_sidecar_update_does_not_fail_the_upload(rclone, recording_command, monkeypatch):
    # The files arrived; the next sync re-hashes anything the sidecar lacks.
    warnings = []
    monkeypatch.setattr(sync, "upload_hash_sidecar_files", lambda **kwargs: False)
    monkeypatch.setattr(sync.logger, "log_warning", lambda message: warnings.append(message))

    assert run("upload_files_to_remote", local_root = "/locker") is True
    assert warnings


###########################################################
# Directory listing and mounting extras
###########################################################

def test_a_listing_without_rclone_is_refused_quietly(no_rclone, quiet, recording_command):
    assert sync.list_files(REMOTE, REMOTE_TYPE, REMOTE_PATH) is False


def test_a_verbose_mount_writes_a_log(rclone, recording_command, tmp_path):
    mount_point = tmp_path / "mount"
    mount_point.mkdir()
    sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, str(mount_point), verbose = True)

    assert recording_command.value_after("--log-level") == "INFO"


def test_a_mount_point_that_cannot_be_made_empty_is_refused(rclone, quiet, recording_command, monkeypatch, tmp_path):
    monkeypatch.setattr(sync.platform_info, "is_unix_platform", lambda: True)
    monkeypatch.setattr(sync.fileops, "make_directory", lambda **kwargs: False)

    assert sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, str(tmp_path / "absent")) is False
    assert recording_command.ran() is False


def test_a_pretend_mount_creates_no_mount_point(rclone, recording_command, monkeypatch, tmp_path):
    target = tmp_path / "new-mount"
    monkeypatch.setattr(sync.platform_info, "is_unix_platform", lambda: True)

    assert sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, str(target), pretend_run = True) is True
    assert not target.exists()


def test_a_non_unix_mount_runs_in_the_foreground(rclone, recording_command, monkeypatch, tmp_path):
    monkeypatch.setattr(sync.platform_info, "is_unix_platform", lambda: False)
    sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, str(tmp_path / "M"))

    assert "--daemon" not in recording_command.only()
