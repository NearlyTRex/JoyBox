# Third-party imports
import pytest

# Local imports
from joybox import sync
from sync_helpers import (
    REMOTE, REMOTE_TYPE, LOCAL, REMOTE_PATH, positional_arguments, record)


###########################################################
# Mirroring
#
# pull and push are both rclone sync, differing only in direction. Each
# deletes whatever the source does not have, so which way round they run is
# the difference between restoring the library and erasing it.
###########################################################

def test_a_pull_makes_the_local_match_the_remote(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.pull_files_from_remote(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)
    arguments = positional_arguments(recorder.only())

    assert arguments[0] == "sync"
    assert arguments[1].startswith(REMOTE + ":")
    assert arguments[2] == LOCAL


def test_a_push_makes_the_remote_match_the_local(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.push_files_to_remote(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)
    arguments = positional_arguments(recorder.only())

    assert arguments[0] == "sync"
    assert arguments[1] == LOCAL
    assert arguments[2].startswith(REMOTE + ":")


def test_a_pull_and_a_push_are_exact_opposites(rclone, monkeypatch):
    # The one property that matters: neither can be the other by accident.
    recorder = record(monkeypatch)
    sync.pull_files_from_remote(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)
    pull = positional_arguments(recorder.calls[0]["cmd"])
    recorder.calls.clear()
    sync.push_files_to_remote(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)
    push = positional_arguments(recorder.calls[0]["cmd"])

    assert pull[1] == push[2]
    assert pull[2] == push[1]


@pytest.mark.parametrize("call", ["pull_files_from_remote", "push_files_to_remote"])
def test_a_mirror_passes_its_excludes(rclone, monkeypatch, call):
    recorder = record(monkeypatch)
    getattr(sync, call)(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL, excludes = ["*.tmp"])

    assert recorder.value_after("--exclude") == "*.tmp"


@pytest.mark.parametrize("call", ["pull_files_from_remote", "push_files_to_remote"])
def test_a_pretend_mirror_is_a_dry_run(rclone, monkeypatch, call):
    recorder = record(monkeypatch)
    getattr(sync, call)(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL, pretend_run = True)

    assert "--dry-run" in recorder.only()


@pytest.mark.parametrize("call", ["pull_files_from_remote", "push_files_to_remote"])
def test_a_failed_mirror_is_reported(rclone, monkeypatch, call):
    record(monkeypatch, returncode = 1)

    assert getattr(sync, call)(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL) is False


@pytest.mark.parametrize("call", ["pull_files_from_remote", "push_files_to_remote"])
def test_a_mirror_without_rclone_is_refused(no_rclone, recording_command, call):
    assert getattr(sync, call)(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL) is False
    assert recording_command.ran() is False


###########################################################
# Merging
###########################################################

def test_a_merge_runs_bisync(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.merge_files_both_ways(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)
    arguments = positional_arguments(recorder.only())

    assert arguments[0] == "bisync"
    assert arguments[1] == LOCAL
    assert arguments[2].startswith(REMOTE + ":")


def test_a_merge_always_checks_access(rclone, monkeypatch):
    # bisync refuses to run against a path it cannot verify, which is what
    # stops it deleting both sides after a bad mount.
    recorder = record(monkeypatch)
    sync.merge_files_both_ways(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)

    assert "--check-access" in recorder.only()


def test_a_merge_does_not_resync_by_default(rclone, monkeypatch):
    # resync discards bisync's state and treats one side as authoritative.
    recorder = record(monkeypatch)
    sync.merge_files_both_ways(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)

    assert "--resync" not in recorder.only()


def test_a_merge_can_resync_when_asked(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.merge_files_both_ways(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL, resync = True)

    assert "--resync" in recorder.only()


def test_a_merge_is_not_a_one_way_sync(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.merge_files_both_ways(REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL)

    assert "sync" not in positional_arguments(recorder.only())[:1]


def test_a_failed_merge_is_reported(rclone, monkeypatch):
    record(monkeypatch, returncode = 1)

    assert sync.merge_files_both_ways(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, LOCAL) is False


###########################################################
# Listing
###########################################################

def test_files_are_listed_with_hashes(rclone, monkeypatch):
    import json as _json

    entries = [
        {"Path": "Roms/game.zip", "Name": "game.zip", "Size": 100,
         "Hashes": {"md5": "abc123"}, "IsDir": False, "ModTime": "2024-01-01T00:00:00Z"},
    ]
    recorder = record(monkeypatch, output = _json.dumps(entries))
    built = sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH)

    assert "lsjson" in recorder.text()
    assert "--recursive" in recorder.only()
    assert built


def test_a_listing_with_no_output_is_empty(rclone, monkeypatch):
    record(monkeypatch, output = "")

    assert sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH) == {}


def test_a_malformed_listing_is_empty(rclone, monkeypatch):
    record(monkeypatch, output = "not json at all")

    assert sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH) == {}


def test_a_listing_without_rclone_is_empty(no_rclone, recording_command):
    assert sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH) == {}


