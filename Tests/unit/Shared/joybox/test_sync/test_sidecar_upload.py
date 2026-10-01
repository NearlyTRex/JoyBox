# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import sync
from sync_helpers import REMOTE, REMOTE_TYPE, make_database, read_database


###########################################################
# Uploading the hash sidecar
#
# The sidecar is the only record of hashes on remotes that cannot compute
# them. Every file uploaded must land in it under its path from the sidecar
# root, and an update must never replace the remote copy with a smaller one.
###########################################################

ROOT = "/Gaming"
TARGET = "/Gaming/Roms"


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "local"
    (root / "Games" / "Extra").mkdir(parents = True)
    (root / "top.zip").write_text("top")
    (root / "Games" / "game.zip").write_text("game")
    (root / "Games" / "Extra" / "dlc.zip").write_text("dlc")
    (root / ".hidden").mkdir()
    (root / ".hidden" / "secret.zip").write_text("secret")
    return root


@pytest.fixture(autouse = True)
def silent(monkeypatch):
    for name in ["log_info", "log_warning", "log_error"]:
        monkeypatch.setattr(sync.logger, name, lambda *args, **kwargs: None)


def upload(local_path, remote_path = TARGET, **kwargs):
    return sync.upload_hash_sidecar_files(
        remote_name = REMOTE, remote_type = REMOTE_TYPE, remote_path = remote_path,
        local_path = str(local_path), local_root = ROOT, **kwargs)


def test_every_file_in_a_tree_is_recorded(tree, remote, temp_dirs):
    assert upload(tree) is True

    assert sorted(read_database(remote.store)) == [
        "Roms/Games/Extra/dlc.zip", "Roms/Games/game.zip", "Roms/top.zip"]


def test_a_recorded_file_carries_its_hash_size_and_time(tree, remote, temp_dirs):
    upload(tree)
    entry = read_database(remote.store)["Roms/top.zip"]

    assert entry["hash"] == sync.hashing.calculate_file_md5(str(tree / "top.zip"))
    assert entry["size"] == 3
    assert entry["mtime"] > 0


def test_the_database_goes_back_beside_the_sidecar_root(tree, remote, temp_dirs):
    upload(tree)

    assert remote.uploads[0]["remote_path"] == ROOT
    assert os.path.basename(remote.uploads[0]["local_path"]) == sync.HASH_DATABASE_FILE


def test_a_single_uploaded_file_is_recorded(tree, remote, temp_dirs):
    # rclone copy puts a single file inside the remote path.
    assert upload(tree / "top.zip", remote_path = TARGET + "/Games") is True

    assert list(read_database(remote.store)) == ["Roms/Games/top.zip"]


def test_hidden_directories_are_not_recorded(tree, remote, temp_dirs):
    upload(tree)

    assert not any("secret" in path for path in read_database(remote.store))


def test_excluded_directories_are_not_recorded(tree, remote, temp_dirs):
    upload(tree, excludes = ["Games"])

    assert list(read_database(remote.store)) == ["Roms/top.zip"]


def test_existing_records_are_kept(tree, remote, temp_dirs):
    make_database(remote.store, [{"file_path": "Other/kept.zip", "hash": "kkkk"}])
    upload(tree)

    assert "Other/kept.zip" in read_database(remote.store)
    assert remote.downloads[0]["remote_path"] == sync.get_hash_database_path(ROOT)


def test_an_existing_record_is_refreshed_by_default(tree, remote, temp_dirs):
    make_database(remote.store, [{"file_path": "Roms/top.zip", "hash": "stale"}])
    upload(tree)

    assert read_database(remote.store)["Roms/top.zip"]["hash"] != "stale"


def test_an_existing_record_can_be_left_alone(tree, remote, temp_dirs):
    make_database(remote.store, [{"file_path": "Roms/top.zip", "hash": "stale"}])
    upload(tree, skip_existing = True)
    recorded = read_database(remote.store)

    assert recorded["Roms/top.zip"]["hash"] == "stale"
    assert "Roms/Games/game.zip" in recorded


def test_a_failed_database_download_keeps_the_remote_copy(tree, remote, temp_dirs):
    # Uploading a fresh database here would drop every other record.
    make_database(remote.store, [{"file_path": "Other/kept.zip", "hash": "kkkk"}])
    remote.download_result = False

    assert upload(tree) is False
    assert remote.uploads == []
    assert list(read_database(remote.store)) == ["Other/kept.zip"]


def test_a_download_that_leaves_no_database_is_a_failure(tree, remote, temp_dirs, monkeypatch):
    make_database(remote.store, [{"file_path": "Other/kept.zip", "hash": "kkkk"}])
    monkeypatch.setattr(sync, "download_files_from_remote", lambda **kwargs: True)

    assert upload(tree) is False
    assert remote.uploads == []


def test_the_download_hands_on_its_run_flags(tree, remote, temp_dirs):
    make_database(remote.store, [{"file_path": "Other/kept.zip", "hash": "kkkk"}])
    upload(tree, exit_on_failure = True, verbose = True)

    assert remote.downloads[0]["exit_on_failure"] is True
    assert remote.downloads[0]["verbose"] is True


def test_a_pretend_run_changes_nothing_and_cleans_up(tree, remote, temp_dirs):
    make_database(remote.store, [{"file_path": "Other/kept.zip", "hash": "kkkk"}])

    assert upload(tree, pretend_run = True) is True
    assert remote.uploads[0]["pretend_run"] is True
    assert list(read_database(remote.store)) == ["Other/kept.zip"]
    assert not os.path.exists(temp_dirs[0])


def test_the_temporary_directory_is_removed_after_success(tree, remote, temp_dirs):
    upload(tree)

    assert not os.path.exists(temp_dirs[0])


def test_the_temporary_directory_is_removed_after_a_failure(tree, remote, temp_dirs):
    make_database(remote.store, [{"file_path": "Other/kept.zip", "hash": "kkkk"}])
    remote.download_result = False
    upload(tree)

    assert not os.path.exists(temp_dirs[0])


def test_the_temporary_directory_is_removed_after_an_error(tree, remote, temp_dirs, monkeypatch):
    def explode(**kwargs):
        raise RuntimeError("disk gone")

    monkeypatch.setattr(sync, "build_hash_sidecar_data", explode)

    with pytest.raises(RuntimeError):
        upload(tree)
    assert not os.path.exists(temp_dirs[0])


def test_no_temporary_directory_is_a_failure(tree, remote, monkeypatch):
    monkeypatch.setattr(sync.fileops, "create_temporary_directory", lambda **kwargs: (False, None))

    assert upload(tree) is False


@pytest.mark.parametrize("name", ["empty", "absent"])
def test_nothing_to_hash_uploads_nothing(tmp_path, remote, temp_dirs, name):
    (tmp_path / "empty").mkdir()

    assert upload(tmp_path / name) is True
    assert remote.uploads == []
    assert not os.path.exists(temp_dirs[0])


def test_a_remote_path_outside_the_root_is_recorded_from_the_top(tree, remote, temp_dirs):
    upload(tree / "top.zip", remote_path = "/Elsewhere")

    assert list(read_database(remote.store)) == ["Elsewhere/top.zip"]


def test_a_failed_database_upload_is_a_failure(tree, remote, temp_dirs):
    remote.upload_result = False

    assert upload(tree) is False


###########################################################
# Files that cannot be hashed
###########################################################

@pytest.fixture
def unreadable(monkeypatch):
    original = sync.hashing.calculate_file_md5

    def calculate(src, **kwargs):
        if os.path.basename(src) == "game.zip":
            return ""
        return original(src, **kwargs)

    monkeypatch.setattr(sync.hashing, "calculate_file_md5", calculate)


@pytest.fixture
def all_large(monkeypatch):
    original = sync.build_hash_sidecar_directory_list

    def build(**kwargs):
        small, large = original(**kwargs)
        return [], small + large

    monkeypatch.setattr(sync, "build_hash_sidecar_directory_list", build)


def test_an_unhashable_file_fails_the_update_but_keeps_the_rest(tree, remote, temp_dirs, unreadable):
    assert upload(tree) is False

    assert sorted(read_database(remote.store)) == ["Roms/Games/Extra/dlc.zip", "Roms/top.zip"]


def test_an_unhashable_file_stops_the_update_when_asked(tree, remote, temp_dirs, unreadable):
    assert upload(tree, exit_on_failure = True, parallel_dirs = 1) is False
    assert remote.uploads == []


def test_large_directories_are_recorded_too(tree, remote, temp_dirs, all_large):
    assert upload(tree) is True

    assert len(read_database(remote.store)) == 3


def test_an_unhashable_file_in_a_large_directory_fails_the_update(tree, remote, temp_dirs, all_large, unreadable):
    assert upload(tree) is False

    assert len(read_database(remote.store)) == 2


def test_an_unhashable_file_in_a_large_directory_stops_the_update_when_asked(tree, remote, temp_dirs, all_large, unreadable):
    assert upload(tree, exit_on_failure = True) is False
    assert remote.uploads == []
    assert not os.path.exists(temp_dirs[0])
