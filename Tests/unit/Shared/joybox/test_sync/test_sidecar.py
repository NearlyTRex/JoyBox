# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import sync
from sync_helpers import REMOTE, REMOTE_TYPE, REMOTE_PATH, make_database, record


###########################################################
# Hash listings from rclone
#
# rclone's JSON is parsed field by field. A listing of the wrong shape, or a
# field that is present but null, must drop that entry rather than abort the
# whole listing.
###########################################################

def listing(monkeypatch, output, returncode = 0):
    return record(monkeypatch, output = output, returncode = returncode)


def test_a_failed_listing_is_a_failure(rclone, quiet, monkeypatch):
    # A partial listing would read as files missing from the remote.
    listing(monkeypatch, '[{"Path": "a.zip", "Hashes": {"MD5": "aaaa"}}]', returncode = 1)

    assert sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None


@pytest.mark.parametrize("output", ['{"Path": "a.zip"}', '"a.zip"', "42"])
def test_a_listing_that_is_not_a_list_is_a_failure(rclone, quiet, monkeypatch, output):
    listing(monkeypatch, output)

    assert sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None


def test_entries_of_the_wrong_shape_are_skipped(rclone, monkeypatch):
    listing(monkeypatch, '["a.zip", 7, null, {"Path": "b.zip", "Hashes": {"MD5": "bbbb"}}]')

    assert list(sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH)) == ["b.zip"]


@pytest.mark.parametrize("path", [None, "", 5])
def test_an_entry_without_a_usable_path_is_skipped(rclone, monkeypatch, path):
    import json
    listing(monkeypatch, json.dumps([{"Path": path, "Hashes": {"MD5": "aaaa"}}]))

    assert sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH) == {}


def test_null_fields_fall_back_to_their_defaults(rclone, monkeypatch):
    listing(monkeypatch, '[{"Path": "a.zip", "Hashes": null, "Size": null, "ModTime": null}]')

    entry = sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH)["a.zip"]

    assert entry["hash"] == ""
    assert entry["size"] == 0
    assert entry["mtime"] == 0


def test_a_null_hash_value_reads_as_no_hash(rclone, monkeypatch):
    listing(monkeypatch, '[{"Path": "a.zip", "Hashes": {"MD5": null}}]')

    assert sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH)["a.zip"]["hash"] == ""


def test_an_unknown_hash_type_reads_as_no_hash(rclone, monkeypatch):
    listing(monkeypatch, '[{"Path": "a.zip", "Hashes": {"MD5": "aaaa"}}]')

    listed = sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH, hash_type = "crc32")

    assert listed["a.zip"]["hash"] == ""


def test_a_verbose_listing_reports_its_count(rclone, monkeypatch):
    listing(monkeypatch, '[{"Path": "a.zip", "Hashes": {"MD5": "aaaa"}}]')
    messages = []
    monkeypatch.setattr(sync.logger, "log_info", lambda message: messages.append(message))
    sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH, verbose = True)

    assert "Loaded 1 file hashes" in messages


###########################################################
# Hash listings from the sidecar database
###########################################################

def test_a_sidecar_listing_reads_the_database(remote, temp_dirs):
    make_database(remote.store, [
        {"file_path": "Games/a.zip", "hash": "aaaa", "size": 10, "mtime": 5.0}])

    listed = sync.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH)

    assert listed == {"Games/a.zip": {
        "filename": "a.zip", "dir": "Games", "hash": "aaaa", "size": 10, "mtime": 5.0}}
    assert remote.downloads[0]["remote_path"] == sync.get_hash_database_path(REMOTE_PATH)


def test_null_sidecar_fields_fall_back_to_their_defaults(remote, temp_dirs):
    make_database(remote.store, [{"file_path": "a.zip", "hash": "aaaa"}])

    entry = sync.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH)["a.zip"]

    assert entry["size"] == 0
    assert entry["mtime"] == 0


def test_a_sidecar_entry_without_a_path_is_skipped(remote, temp_dirs):
    make_database(remote.store, [
        {"file_path": "", "hash": "aaaa"}, {"file_path": "b.zip", "hash": "bbbb"}])

    assert list(sync.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH)) == ["b.zip"]


def test_a_remote_without_a_sidecar_lists_nothing(remote, temp_dirs):
    assert sync.list_files_with_hashes_from_sidecar(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, verbose = True) == {}
    assert not os.path.exists(temp_dirs[0])


def test_a_quiet_listing_of_a_remote_without_a_sidecar_lists_nothing(remote, temp_dirs):
    assert sync.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH) == {}


def test_a_sidecar_is_read_for_real_on_a_pretend_run(remote, temp_dirs):
    make_database(remote.store, [{"file_path": "a.zip", "hash": "aaaa"}])

    assert sync.list_files_with_hashes_from_sidecar(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, pretend_run = True)
    assert remote.downloads[0]["pretend_run"] is False


def test_the_sidecar_download_directory_is_removed(remote, temp_dirs, monkeypatch):
    make_database(remote.store, [{"file_path": "a.zip", "hash": "aaaa"}])
    messages = []
    monkeypatch.setattr(sync.logger, "log_info", lambda message: messages.append(message))
    sync.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH, verbose = True)

    assert not os.path.exists(temp_dirs[0])
    assert "Loaded 1 file hashes from database" in messages


def test_a_sidecar_listing_without_a_temporary_directory_is_a_failure(quiet, monkeypatch):
    monkeypatch.setattr(sync.fileops, "create_temporary_directory", lambda **kwargs: (False, None))

    assert sync.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None


def test_a_corrupt_sidecar_is_a_failure_and_still_cleans_up(remote, temp_dirs, quiet):
    remote.store.write_text("not a database")

    assert sync.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None
    assert not os.path.exists(temp_dirs[0])


def test_a_sidecar_that_fails_to_download_is_a_failure(remote, temp_dirs, quiet):
    # The sidecar is there, so an empty map would read as a remote with no hashes.
    make_database(remote.store, [{"file_path": "a.zip", "hash": "aaaa"}])
    remote.download_result = False

    assert sync.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None
    assert not os.path.exists(temp_dirs[0])


def test_a_sidecar_download_that_leaves_no_file_is_a_failure(remote, temp_dirs, quiet, monkeypatch):
    make_database(remote.store, [{"file_path": "a.zip", "hash": "aaaa"}])
    monkeypatch.setattr(sync, "download_files_from_remote", lambda **kwargs: True)

    assert sync.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None


def test_a_remote_without_a_sidecar_is_not_downloaded_from(remote, temp_dirs):
    assert sync.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH) == {}
    assert remote.downloads == []


###########################################################
# Clearing the sidecar
###########################################################

def test_clearing_the_sidecar_deletes_only_the_database(monkeypatch):
    deleted = []
    monkeypatch.setattr(
        sync, "delete_file_on_remote", lambda **kwargs: deleted.append(kwargs) or True)

    assert sync.clear_hash_sidecar_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, pretend_run = True) is True
    assert deleted[0]["remote_path"] == sync.get_hash_database_path(REMOTE_PATH)
    assert deleted[0]["pretend_run"] is True


###########################################################
# Hashing local files
###########################################################

@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "local"
    (root / "Games" / "Extra").mkdir(parents = True)
    (root / "top.zip").write_text("top")
    (root / "Games" / "game.zip").write_text("game")
    (root / "Games" / "Extra" / "dlc.zip").write_text("dlc")
    (root / ".hidden").mkdir()
    (root / ".hidden" / "secret.zip").write_text("secret")
    (root / "Empty").mkdir()
    return root


def test_a_single_file_is_hashed_under_its_name(tree):
    data = sync.build_hash_sidecar_data(str(tree / "top.zip"))

    assert list(data) == ["top.zip"]
    assert len(data["top.zip"]["hash"]) == 32
    assert data["top.zip"]["size"] == 3


def test_a_directory_is_hashed_throughout_by_default(tree):
    data = sync.build_hash_sidecar_data(str(tree / "Games"))

    assert sorted(data) == ["Extra/dlc.zip", "game.zip"]


def test_a_directory_can_be_limited_to_named_files(tree):
    data = sync.build_hash_sidecar_data(str(tree / "Games"), file_list = ["game.zip", "absent.zip"])

    assert list(data) == ["game.zip"]


def test_a_pretend_hash_records_nothing(tree):
    assert sync.build_hash_sidecar_data(str(tree / "top.zip"), pretend_run = True) == {}
    assert sync.build_hash_sidecar_data(str(tree / "Games"), pretend_run = True) == {}


def test_a_missing_path_hashes_nothing(tmp_path):
    assert sync.build_hash_sidecar_data(str(tmp_path / "absent")) == {}


def test_a_large_hashing_run_reports_progress(tmp_path, monkeypatch):
    for index in range(101):
        (tmp_path / ("%03d.bin" % index)).write_text(str(index))
    messages = []
    monkeypatch.setattr(sync.logger, "log_info", lambda message: messages.append(message))

    assert len(sync.build_hash_sidecar_data(str(tmp_path), verbose = True)) == 101
    assert "  Hashing 101 files..." in messages
    assert "  Hashed 100/101 files..." in messages


###########################################################
# Hashing units
###########################################################

def test_every_directory_with_files_is_a_unit(tree):
    small, large = sync.build_hash_sidecar_directory_list(str(tree))

    assert sorted((os.path.relpath(d["path"], str(tree)), d["files"]) for d in small) == [
        (".", ["top.zip"]), ("Games", ["game.zip"]), (os.path.join("Games", "Extra"), ["dlc.zip"])]
    assert large == []


def test_excluded_directories_are_not_units(tree):
    small, large = sync.build_hash_sidecar_directory_list(str(tree), excludes = ["Games/Extra"])

    assert os.path.join(str(tree), "Games", "Extra") not in [d["path"] for d in small]


def test_a_directory_over_a_threshold_is_large(tree):
    small, large = sync.build_hash_sidecar_directory_list(
        str(tree), large_file_count = 0, large_total_size = None)

    assert small == []
    assert len(large) == 3


def test_a_directory_over_the_size_threshold_is_large(tree):
    small, large = sync.build_hash_sidecar_directory_list(str(tree), large_total_size = 3)

    assert [d["files"] for d in large] == [["game.zip"]]


@pytest.mark.parametrize("path,root,expected", [
    ("/Gaming", "/Gaming", ""),
    ("/Gaming", "/Gaming/", ""),
    ("/Gaming/Roms", "/Gaming", "Roms"),
    ("/Gaming/Roms/A", "/Gaming/", "Roms/A"),
    ("/GamingX/Roms", "/Gaming", None),
    ("/Gaming/Roms", "/", "Gaming/Roms"),
])
def test_a_remote_path_is_made_relative_to_its_root(path, root, expected):
    assert sync.get_remote_relative_path(path, root) == expected
