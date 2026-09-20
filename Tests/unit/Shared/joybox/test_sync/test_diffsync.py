# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import sync
from sync_helpers import REMOTE, REMOTE_TYPE, LOCAL, REMOTE_PATH


###########################################################
# Diff driven sync
#
# The decision core: given a diff between local and remote, what gets
# uploaded, what gets downloaded, and what gets recycled. A file in the wrong
# bucket is either lost or silently reverted to an older copy.
###########################################################

@pytest.fixture
def diff_dir(tmp_path):
    target = tmp_path / "diffs"
    target.mkdir()
    return target


def write_diff(diff_dir, name, *entries):
    (diff_dir / name).write_text("".join(entry + "\n" for entry in entries))


@pytest.fixture
def transfers(monkeypatch):
    calls = {"upload": [], "download": [], "recycle": []}
    monkeypatch.setattr(
        sync, "upload_files_to_remote",
        lambda **kwargs: calls["upload"].append(kwargs) or True)
    monkeypatch.setattr(
        sync, "download_files_from_remote",
        lambda **kwargs: calls["download"].append(kwargs) or True)
    monkeypatch.setattr(
        sync, "recycle_files_on_remote",
        lambda **kwargs: calls["recycle"].append(kwargs) or True)
    monkeypatch.setattr(sync.logger, "log_info", lambda *a, **k: None)
    monkeypatch.setattr(sync.logger, "log_warning", lambda *a, **k: None)
    return calls


def run_diff_sync(diff_dir, **kwargs):
    defaults = dict(
        remote_name = REMOTE, remote_type = REMOTE_TYPE,
        remote_path = REMOTE_PATH, local_path = LOCAL, diff_dir = str(diff_dir))
    defaults.update(kwargs)
    return sync.diff_sync_files(**defaults)


def listed(calls, kind):
    # The transfer helpers are handed a file list rather than paths
    return [entry.get("files_from") for entry in calls[kind]]


###########################################################
# Buckets
###########################################################

def test_a_file_missing_on_the_remote_is_uploaded(diff_dir, transfers):
    write_diff(diff_dir, "diff_missing_dest.txt", "new.zip")

    assert run_diff_sync(diff_dir) is True
    assert transfers["upload"]
    assert transfers["download"] == []


def test_a_file_missing_locally_is_downloaded(diff_dir, transfers):
    write_diff(diff_dir, "diff_missing_src.txt", "onlyremote.zip")
    run_diff_sync(diff_dir)

    assert transfers["download"]
    assert transfers["upload"] == []


def test_nothing_missing_transfers_nothing(diff_dir, transfers):
    assert run_diff_sync(diff_dir) is True
    assert transfers["upload"] == []
    assert transfers["download"] == []
    assert transfers["recycle"] == []


def test_both_directions_can_happen_in_one_run(diff_dir, transfers):
    write_diff(diff_dir, "diff_missing_dest.txt", "new.zip")
    write_diff(diff_dir, "diff_missing_src.txt", "onlyremote.zip")
    run_diff_sync(diff_dir)

    assert transfers["upload"]
    assert transfers["download"]


def test_blank_diff_lines_are_ignored(diff_dir, transfers):
    (diff_dir / "diff_missing_dest.txt").write_text("\n\n   \n")
    run_diff_sync(diff_dir)

    assert transfers["upload"] == []


def test_a_missing_diff_file_is_not_an_error(diff_dir, transfers):
    assert run_diff_sync(diff_dir) is True


###########################################################
# Recycling instead of downloading
###########################################################

def test_a_locally_deleted_file_can_be_recycled(diff_dir, transfers):
    # Deleting locally then syncing should remove it remotely, reversibly,
    # rather than pulling it back down.
    write_diff(diff_dir, "diff_missing_src.txt", "deleted.zip")
    run_diff_sync(diff_dir, recycle_missing = True)

    assert transfers["recycle"]
    assert transfers["download"] == []


def test_recycling_is_not_the_default(diff_dir, transfers):
    write_diff(diff_dir, "diff_missing_src.txt", "onlyremote.zip")
    run_diff_sync(diff_dir)

    assert transfers["recycle"] == []
    assert transfers["download"]


def test_recycling_uses_the_named_folder(diff_dir, transfers):
    write_diff(diff_dir, "diff_missing_src.txt", "deleted.zip")
    run_diff_sync(diff_dir, recycle_missing = True, recycle_folder = ".trash")

    assert transfers["recycle"][0]["recycle_folder"] == ".trash"


def test_a_failed_recycle_stops_the_run(diff_dir, transfers, monkeypatch):
    monkeypatch.setattr(sync, "recycle_files_on_remote", lambda **kwargs: False)
    write_diff(diff_dir, "diff_missing_src.txt", "deleted.zip")

    assert run_diff_sync(diff_dir, recycle_missing = True) is False


###########################################################
# Changed files
###########################################################

@pytest.fixture
def clocks(monkeypatch):
    times = {"local": {}, "remote": {}}
    monkeypatch.setattr(
        sync, "get_path_mod_time",
        lambda remote_name, remote_type, remote_path, **kwargs:
            times["remote"].get(os.path.basename(remote_path)))
    monkeypatch.setattr(
        sync.paths, "get_file_mod_time",
        lambda path: times["local"].get(os.path.basename(path)))
    return times


def test_a_newer_local_file_is_uploaded(diff_dir, transfers, clocks):
    write_diff(diff_dir, "diff_intersected.txt", "game.zip")
    clocks["local"]["game.zip"] = 2000
    clocks["remote"]["game.zip"] = 1000
    run_diff_sync(diff_dir)

    assert transfers["upload"]
    assert transfers["download"] == []


def test_a_newer_remote_file_is_downloaded(diff_dir, transfers, clocks):
    write_diff(diff_dir, "diff_intersected.txt", "game.zip")
    clocks["local"]["game.zip"] = 1000
    clocks["remote"]["game.zip"] = 2000
    run_diff_sync(diff_dir)

    assert transfers["download"]
    assert transfers["upload"] == []


def test_an_equally_aged_file_is_left_alone(diff_dir, transfers, clocks):
    # Same time means same content as far as the sync is concerned.
    write_diff(diff_dir, "diff_intersected.txt", "game.zip")
    clocks["local"]["game.zip"] = 1000
    clocks["remote"]["game.zip"] = 1000
    run_diff_sync(diff_dir)

    assert transfers["upload"] == []
    assert transfers["download"] == []


def test_an_unreadable_timestamp_leaves_the_file_alone(diff_dir, transfers, clocks):
    # Guessing a direction here would overwrite whichever side is newer.
    write_diff(diff_dir, "diff_intersected.txt", "game.zip")
    clocks["local"]["game.zip"] = None
    clocks["remote"]["game.zip"] = 2000
    run_diff_sync(diff_dir)

    assert transfers["upload"] == []
    assert transfers["download"] == []


def test_changed_files_can_be_left_out_entirely(diff_dir, transfers, clocks):
    write_diff(diff_dir, "diff_intersected.txt", "game.zip")
    clocks["local"]["game.zip"] = 2000
    clocks["remote"]["game.zip"] = 1000
    run_diff_sync(diff_dir, sync_changed = False)

    assert transfers["upload"] == []
    assert transfers["download"] == []


def test_several_changed_files_go_their_own_ways(diff_dir, transfers, clocks):
    write_diff(diff_dir, "diff_intersected.txt", "newer_local.zip", "newer_remote.zip")
    clocks["local"] = {"newer_local.zip": 2000, "newer_remote.zip": 1000}
    clocks["remote"] = {"newer_local.zip": 1000, "newer_remote.zip": 2000}
    run_diff_sync(diff_dir)

    assert transfers["upload"]
    assert transfers["download"]


###########################################################
# Exclusions
###########################################################

def test_a_missing_diff_directory_is_refused(tmp_path, transfers):
    assert sync.diff_sync_files(
        remote_name = REMOTE, remote_type = REMOTE_TYPE,
        remote_path = REMOTE_PATH, local_path = LOCAL,
        diff_dir = str(tmp_path / "absent")) is False


def test_a_failed_upload_stops_the_run(diff_dir, transfers, monkeypatch):
    monkeypatch.setattr(sync, "upload_files_to_remote", lambda **kwargs: False)
    write_diff(diff_dir, "diff_missing_dest.txt", "new.zip")

    assert run_diff_sync(diff_dir) is False


def test_a_failed_download_stops_the_run(diff_dir, transfers, monkeypatch):
    monkeypatch.setattr(sync, "download_files_from_remote", lambda **kwargs: False)
    write_diff(diff_dir, "diff_missing_src.txt", "onlyremote.zip")

    assert run_diff_sync(diff_dir) is False
