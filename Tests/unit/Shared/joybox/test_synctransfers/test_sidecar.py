# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import fileops
from joybox import logger
from joybox import sync
from joybox import synctransfers
from sync_helpers import REMOTE, REMOTE_TYPE, REMOTE_PATH, make_database


###########################################################
# Hash listings from the sidecar database
###########################################################

def test_a_sidecar_listing_reads_the_database(remote, temp_dirs):
    make_database(remote.store, [
        {"file_path": "Games/a.zip", "hash": "aaaa", "size": 10, "mtime": 5.0}])

    listed = synctransfers.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH)

    assert listed == {"Games/a.zip": {
        "filename": "a.zip", "dir": "Games", "hash": "aaaa", "size": 10, "mtime": 5.0}}
    assert remote.downloads[0]["remote_path"] == synctransfers.get_hash_database_path(REMOTE_PATH)


def test_null_sidecar_fields_fall_back_to_their_defaults(remote, temp_dirs):
    make_database(remote.store, [{"file_path": "a.zip", "hash": "aaaa"}])

    entry = synctransfers.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH)["a.zip"]

    assert entry["size"] == 0
    assert entry["mtime"] == 0


def test_a_sidecar_entry_without_a_path_is_skipped(remote, temp_dirs):
    make_database(remote.store, [
        {"file_path": "", "hash": "aaaa"}, {"file_path": "b.zip", "hash": "bbbb"}])

    assert list(synctransfers.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH)) == ["b.zip"]


def test_a_remote_without_a_sidecar_lists_nothing(remote, temp_dirs):
    assert synctransfers.list_files_with_hashes_from_sidecar(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, verbose = True) == {}
    assert not os.path.exists(temp_dirs[0])


def test_a_quiet_listing_of_a_remote_without_a_sidecar_lists_nothing(remote, temp_dirs):
    assert synctransfers.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH) == {}


def test_a_sidecar_is_read_for_real_on_a_pretend_run(remote, temp_dirs):
    make_database(remote.store, [{"file_path": "a.zip", "hash": "aaaa"}])

    assert synctransfers.list_files_with_hashes_from_sidecar(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, pretend_run = True)
    assert remote.downloads[0]["pretend_run"] is False


def test_the_sidecar_download_directory_is_removed(remote, temp_dirs, monkeypatch):
    make_database(remote.store, [{"file_path": "a.zip", "hash": "aaaa"}])
    messages = []
    monkeypatch.setattr(logger, "log_info", messages.append)
    synctransfers.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH, verbose = True)

    assert not os.path.exists(temp_dirs[0])
    assert "Loaded 1 file hashes from database" in messages


def test_a_sidecar_listing_without_a_temporary_directory_is_a_failure(quiet, monkeypatch):
    monkeypatch.setattr(fileops, "create_temporary_directory", lambda **kwargs: (False, None))

    assert synctransfers.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None


def test_a_corrupt_sidecar_is_a_failure_and_still_cleans_up(remote, temp_dirs, quiet):
    remote.store.write_text("not a database")

    assert synctransfers.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None
    assert not os.path.exists(temp_dirs[0])


def test_a_sidecar_that_fails_to_download_is_a_failure(remote, temp_dirs, quiet):
    # The sidecar is there, so an empty map would read as a remote with no hashes.
    make_database(remote.store, [{"file_path": "a.zip", "hash": "aaaa"}])
    remote.download_result = False

    assert synctransfers.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None
    assert not os.path.exists(temp_dirs[0])


def test_a_sidecar_download_that_leaves_no_file_is_a_failure(remote, temp_dirs, quiet, monkeypatch):
    make_database(remote.store, [{"file_path": "a.zip", "hash": "aaaa"}])
    monkeypatch.setattr(synctransfers, "download_files_from_remote", lambda **kwargs: True)

    assert synctransfers.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None


def test_a_remote_without_a_sidecar_is_not_downloaded_from(remote, temp_dirs):
    assert synctransfers.list_files_with_hashes_from_sidecar(REMOTE, REMOTE_TYPE, REMOTE_PATH) == {}
    assert remote.downloads == []


###########################################################
# Clearing the sidecar
###########################################################

def test_clearing_the_sidecar_deletes_only_the_database(monkeypatch):
    deleted = []
    monkeypatch.setattr(
        sync, "delete_file_on_remote", lambda **kwargs: deleted.append(kwargs) or True)

    assert synctransfers.clear_hash_sidecar_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, pretend_run = True) is True
    assert deleted[0]["remote_path"] == synctransfers.get_hash_database_path(REMOTE_PATH)
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
    data = synctransfers.build_hash_sidecar_data(str(tree / "top.zip"))

    assert list(data) == ["top.zip"]
    assert len(data["top.zip"]["hash"]) == 32
    assert data["top.zip"]["size"] == 3


def test_a_directory_is_hashed_throughout_by_default(tree):
    data = synctransfers.build_hash_sidecar_data(str(tree / "Games"))

    assert sorted(data) == ["Extra/dlc.zip", "game.zip"]


def test_a_directory_can_be_limited_to_named_files(tree):
    data = synctransfers.build_hash_sidecar_data(str(tree / "Games"), file_list = ["game.zip", "absent.zip"])

    assert list(data) == ["game.zip"]


def test_a_pretend_hash_records_nothing(tree):
    assert synctransfers.build_hash_sidecar_data(str(tree / "top.zip"), pretend_run = True) == {}
    assert synctransfers.build_hash_sidecar_data(str(tree / "Games"), pretend_run = True) == {}


def test_a_missing_path_hashes_nothing(tmp_path):
    assert synctransfers.build_hash_sidecar_data(str(tmp_path / "absent")) == {}


def test_a_large_hashing_run_reports_progress(tmp_path, monkeypatch):
    for index in range(101):
        (tmp_path / ("%03d.bin" % index)).write_text(str(index))
    messages = []
    monkeypatch.setattr(logger, "log_info", messages.append)

    assert len(synctransfers.build_hash_sidecar_data(str(tmp_path), verbose = True)) == 101
    assert "  Hashing 101 files..." in messages
    assert "  Hashed 100/101 files..." in messages


###########################################################
# Hashing units
###########################################################

def test_every_directory_with_files_is_a_unit(tree):
    small, large = synctransfers.build_hash_sidecar_directory_list(str(tree))

    assert sorted((os.path.relpath(d["path"], str(tree)), d["files"]) for d in small) == [
        (".", ["top.zip"]), ("Games", ["game.zip"]), (os.path.join("Games", "Extra"), ["dlc.zip"])]
    assert large == []


def test_excluded_directories_are_not_units(tree):
    small, large = synctransfers.build_hash_sidecar_directory_list(str(tree), excludes = ["Games/Extra"])

    assert os.path.join(str(tree), "Games", "Extra") not in [d["path"] for d in small]
    assert large == []


def test_a_directory_over_a_threshold_is_large(tree):
    small, large = synctransfers.build_hash_sidecar_directory_list(
        str(tree), large_file_count = 0, large_total_size = None)

    assert small == []
    assert len(large) == 3


def test_a_directory_over_the_size_threshold_is_large(tree):
    small, large = synctransfers.build_hash_sidecar_directory_list(str(tree), large_total_size = 3)

    assert [d["files"] for d in large] == [["game.zip"]]
    assert len(small) == 2


@pytest.mark.parametrize("path,root,expected", [
    ("/Gaming", "/Gaming", ""),
    ("/Gaming", "/Gaming/", ""),
    ("/Gaming/Roms", "/Gaming", "Roms"),
    ("/Gaming/Roms/A", "/Gaming/", "Roms/A"),
    ("/GamingX/Roms", "/Gaming", None),
    ("/Gaming/Roms", "/", "Gaming/Roms"),
])
def test_a_remote_path_is_made_relative_to_its_root(path, root, expected):
    assert synctransfers.get_remote_relative_path(path, root) == expected


###########################################################
# Hash database paths
###########################################################

def test_a_hash_database_path_uses_forward_slashes():
    # Remote paths are posix regardless of the host.
    built = synctransfers.get_hash_database_path("Gaming\\Roms")

    assert "\\" not in built


def test_a_hash_database_path_is_under_the_remote_path():
    assert synctransfers.get_hash_database_path("Gaming").startswith("Gaming/")


def test_a_hash_database_path_works_without_a_remote_path():
    assert synctransfers.get_hash_database_path()
