# Local imports
from joybox import sync
from sync_helpers import REMOTE, REMOTE_TYPE, REMOTE_PATH, connection_path, record


###########################################################
# Copying between remotes
###########################################################

OTHER = "backblaze"


def test_a_remote_to_remote_copy_names_both_ends(rclone, recording_command):
    assert sync.copy_remote_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH,
        OTHER, REMOTE_TYPE, "/Backup") is True

    cmd = recording_command.only()
    assert cmd[1] == "copyto"
    assert cmd[2] == connection_path()
    assert cmd[3] == sync.get_remote_connection_path(OTHER, REMOTE_TYPE, "/Backup")


def test_a_remote_to_remote_copy_is_a_dry_run_when_pretending(rclone, recording_command):
    # The transfer never touches this machine, so the dry run has to be asked
    # of rclone itself rather than skipped locally.
    sync.copy_remote_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, OTHER, REMOTE_TYPE, "/Backup",
        pretend_run = True)

    assert "--dry-run" in recording_command.only()


def test_a_remote_to_remote_copy_is_not_a_dry_run_by_default(rclone, recording_command):
    sync.copy_remote_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, OTHER, REMOTE_TYPE, "/Backup")

    assert "--dry-run" not in recording_command.only()


def test_a_failed_remote_to_remote_copy_reports_failure(rclone, monkeypatch):
    record(monkeypatch, returncode = 1)

    assert sync.copy_remote_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, OTHER, REMOTE_TYPE, "/Backup") is False


def test_a_remote_to_remote_copy_without_rclone_reports_failure(no_rclone, recording_command):
    assert sync.copy_remote_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, OTHER, REMOTE_TYPE, "/Backup") is False
    assert recording_command.ran() is False


def test_a_verbose_remote_to_remote_copy_shows_progress_by_default(rclone, recording_command):
    sync.copy_remote_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, OTHER, REMOTE_TYPE, "/Backup", verbose = True)

    assert "--progress" in recording_command.only()


def test_a_remote_to_remote_copy_can_hide_progress(rclone, recording_command):
    sync.copy_remote_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, OTHER, REMOTE_TYPE, "/Backup",
        show_progress = False, verbose = True)

    cmd = recording_command.only()
    assert "--progress" not in cmd
    assert "--verbose" in cmd
