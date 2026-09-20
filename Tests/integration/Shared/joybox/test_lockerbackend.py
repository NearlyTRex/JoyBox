# Imports
import hashlib
import os
import pytest

# Local imports
from joybox import config, lockerbackend


###########################################################
# Locker backends
#
# The layer that decides where a file lands in a locker and which files a scan
# sees. A relative path resolved wrongly writes into the wrong game's folder,
# and an exclude that does not match puts junk into the archive.
###########################################################

class FakeLockerInfo:

    def __init__(self, mount_path, name = "local", locker_type = "Local",
                 local_only = True):
        self.mount_path = mount_path
        self.name = name
        self.locker_type = locker_type
        self.local_only = local_only

    def get_mount_path(self):
        return self.mount_path

    def get_name(self):
        return self.name

    def get_type(self):
        return self.locker_type

    def is_local_only(self):
        return self.local_only

    def get_passphrase(self):
        # Nothing here exercises the encryption paths, which are the only
        # caller, so the fake has no credential to hand back.
        return None

    def get_remote_path(self):
        return "locker"


@pytest.fixture
def locker(tmp_path):
    root = tmp_path / "locker"
    root.mkdir()
    return lockerbackend.LocalBackend(FakeLockerInfo(str(root)))


@pytest.fixture
def stocked(locker):
    root = locker.get_root_path()
    for rel in ["game.zip", "docs/readme.txt", "docs/deep/notes.txt", "logs/run.log"]:
        target = os.path.join(root, rel)
        os.makedirs(os.path.dirname(target), exist_ok = True)
        with open(target, "wb") as handle:
            handle.write(rel.encode("utf-8"))
    return locker


###########################################################
# Roots and relative paths
###########################################################

def test_the_root_path_is_the_mount_path(tmp_path):
    backend = lockerbackend.LocalBackend(FakeLockerInfo("/mnt/locker"))

    assert backend.get_root_path() == "/mnt/locker"


def test_a_path_under_the_root_becomes_relative(locker):
    root = locker.get_root_path()

    assert locker.get_relative_path(os.path.join(root, "games", "game.zip")) == \
        os.path.join("games", "game.zip")


def test_the_leading_separator_is_removed(locker):
    # Without this the joined path would be absolute and escape the locker.
    root = locker.get_root_path()
    relative = locker.get_relative_path(root + os.sep + "game.zip")

    assert not relative.startswith(os.sep)
    assert relative == "game.zip"


def test_the_root_itself_becomes_empty(locker):
    assert locker.get_relative_path(locker.get_root_path()) == ""


def test_a_path_outside_the_root_is_returned_unchanged(locker):
    assert locker.get_relative_path("/elsewhere/game.zip") == "/elsewhere/game.zip"


def test_an_already_relative_path_is_returned_unchanged(locker):
    assert locker.get_relative_path("games/game.zip") == "games/game.zip"


###########################################################
# Listing
###########################################################

def test_every_file_is_listed(stocked):
    hashes = stocked.list_files_with_hashes()

    assert set(hashes) == {
        "game.zip",
        os.path.join("docs", "readme.txt"),
        os.path.join("docs", "deep", "notes.txt"),
        os.path.join("logs", "run.log"),
    }


def test_a_listed_entry_carries_its_hash(stocked):
    entry = stocked.list_files_with_hashes()["game.zip"]

    assert entry["hash"] == hashlib.md5(b"game.zip").hexdigest()


def test_a_listed_entry_carries_its_size_and_name(stocked):
    entry = stocked.list_files_with_hashes()[os.path.join("docs", "readme.txt")]

    assert entry["filename"] == "readme.txt"
    assert entry["dir"] == "docs"
    assert entry["size"] == len(b"docs/readme.txt")
    assert entry["mtime"] > 0


def test_an_empty_locker_lists_nothing(locker):
    assert locker.list_files_with_hashes() == {}


def test_a_missing_locker_lists_nothing(tmp_path):
    backend = lockerbackend.LocalBackend(FakeLockerInfo(str(tmp_path / "absent")))

    assert backend.list_files_with_hashes() == {}


def test_directories_are_not_listed(stocked):
    hashes = stocked.list_files_with_hashes()

    assert "docs" not in hashes
    assert not any(entry["hash"] is None for entry in hashes.values())


def test_parallel_and_serial_listings_agree(stocked):
    # The parallel path collects under a lock; a dropped entry would mean a
    # file silently never syncs.
    parallel = stocked.list_files_with_hashes(parallel_files = 8)
    serial = stocked.list_files_with_hashes(parallel_files = 1)

    assert parallel == serial


def test_a_large_listing_keeps_every_entry(locker):
    root = locker.get_root_path()
    for index in range(200):
        with open(os.path.join(root, "file%03d.bin" % index), "wb") as handle:
            handle.write(b"%d" % index)

    assert len(locker.list_files_with_hashes(parallel_files = 8)) == 200


###########################################################
# Excludes
###########################################################

def test_an_exact_name_is_excluded(stocked):
    hashes = stocked.list_files_with_hashes(excludes = ["game.zip"])

    assert "game.zip" not in hashes


def test_a_glob_is_excluded(stocked):
    hashes = stocked.list_files_with_hashes(excludes = ["*.zip"])

    assert "game.zip" not in hashes
    assert os.path.join("docs", "readme.txt") in hashes


def test_a_directory_tree_is_excluded(stocked):
    hashes = stocked.list_files_with_hashes(excludes = ["logs/**"])

    assert not any(key.startswith("logs") for key in hashes)
    assert "game.zip" in hashes


def test_excluding_a_directory_takes_its_subdirectories(stocked):
    hashes = stocked.list_files_with_hashes(excludes = ["docs/**"])

    assert not any(key.startswith("docs") for key in hashes)


def test_several_excludes_all_apply(stocked):
    hashes = stocked.list_files_with_hashes(excludes = ["*.zip", "logs/**"])

    assert set(hashes) == {
        os.path.join("docs", "readme.txt"),
        os.path.join("docs", "deep", "notes.txt"),
    }


def test_no_excludes_keeps_everything(stocked):
    assert len(stocked.list_files_with_hashes(excludes = [])) == 4


def test_an_exclude_matching_nothing_keeps_everything(stocked):
    assert len(stocked.list_files_with_hashes(excludes = ["*.absent"])) == 4


def test_an_exclude_does_not_match_a_longer_name(stocked):
    # "docs" must not take "docsextra"; a prefix match would drop a sibling.
    root = stocked.get_root_path()
    os.makedirs(os.path.join(root, "docsextra"))
    with open(os.path.join(root, "docsextra", "keep.txt"), "wb") as handle:
        handle.write(b"keep")

    hashes = stocked.list_files_with_hashes(excludes = ["docs/**"])
    assert os.path.join("docsextra", "keep.txt") in hashes


###########################################################
# Existence
###########################################################

def test_a_present_file_exists(stocked):
    assert stocked.file_exists("game.zip") is True


def test_a_missing_file_does_not_exist(stocked):
    assert stocked.file_exists("absent.zip") is False


def test_a_directory_is_not_a_file(stocked):
    assert stocked.file_exists("docs") is False
    assert stocked.path_exists("docs") is True


def test_a_populated_directory_contains_files(stocked):
    assert stocked.path_contains_files("docs") is True


def test_an_empty_directory_contains_nothing(stocked):
    os.makedirs(os.path.join(stocked.get_root_path(), "empty"))

    assert stocked.path_contains_files("empty") is False


def test_a_file_counts_as_containing_files(stocked):
    assert stocked.path_contains_files("game.zip") is True


def test_a_missing_path_contains_nothing(stocked):
    assert stocked.path_contains_files("absent") is False


def test_a_directory_with_only_subdirectories_is_empty(stocked):
    os.makedirs(os.path.join(stocked.get_root_path(), "outer", "inner"))

    assert stocked.path_contains_files("outer") is False


###########################################################
# Copying in
###########################################################

def test_a_file_is_copied_in(tmp_path, locker):
    source = tmp_path / "incoming.bin"
    source.write_bytes(b"payload")

    assert locker.copy_from(str(source), "games/incoming.bin") is True
    assert open(os.path.join(locker.get_root_path(), "games", "incoming.bin"), "rb").read() \
        == b"payload"


def test_copying_in_creates_missing_directories(tmp_path, locker):
    source = tmp_path / "incoming.bin"
    source.write_bytes(b"payload")
    locker.copy_from(str(source), "a/b/c/incoming.bin")

    assert os.path.exists(os.path.join(locker.get_root_path(), "a", "b", "c", "incoming.bin"))


def test_copying_in_can_skip_an_existing_file(tmp_path, locker):
    source = tmp_path / "incoming.bin"
    source.write_bytes(b"new")
    target = os.path.join(locker.get_root_path(), "incoming.bin")
    with open(target, "wb") as handle:
        handle.write(b"old")

    locker.copy_from(str(source), "incoming.bin", skip_existing = True)
    assert open(target, "rb").read() == b"old"


def test_copying_in_overwrites_by_default(tmp_path, locker):
    source = tmp_path / "incoming.bin"
    source.write_bytes(b"new")
    target = os.path.join(locker.get_root_path(), "incoming.bin")
    with open(target, "wb") as handle:
        handle.write(b"old")

    locker.copy_from(str(source), "incoming.bin")
    assert open(target, "rb").read() == b"new"


###########################################################
# Syncing between lockers
###########################################################

@pytest.fixture
def pair(tmp_path):
    source_root = tmp_path / "source"
    dest_root = tmp_path / "dest"
    source_root.mkdir()
    dest_root.mkdir()
    source = lockerbackend.LocalBackend(FakeLockerInfo(str(source_root)))
    dest = lockerbackend.LocalBackend(FakeLockerInfo(str(dest_root)))
    for rel in ["one.bin", "two.bin", "nested/three.bin"]:
        target = source_root / rel
        target.parent.mkdir(parents = True, exist_ok = True)
        target.write_bytes(rel.encode("utf-8"))
    return source, dest


def test_a_file_syncs_between_lockers(pair):
    source, dest = pair

    assert source.get_root_path() != dest.get_root_path()
    assert dest.sync_from(source, "one.bin", "one.bin") is True
    assert dest.file_exists("one.bin") is True


def test_synced_content_matches(pair):
    source, dest = pair
    dest.sync_from(source, "one.bin", "one.bin")
    target = os.path.join(dest.get_root_path(), "one.bin")

    assert open(target, "rb").read() == b"one.bin"


def test_a_sync_can_rename(pair):
    # The action file may map a source path to a different destination name.
    source, dest = pair
    dest.sync_from(source, "one.bin", "renamed.bin")

    assert dest.file_exists("renamed.bin") is True
    assert dest.file_exists("one.bin") is False


def test_a_sync_creates_nested_destinations(pair):
    source, dest = pair
    dest.sync_from(source, "nested/three.bin", "nested/three.bin")

    assert dest.file_exists(os.path.join("nested", "three.bin")) is True


def test_syncing_a_missing_source_reports_failure(pair):
    source, dest = pair

    assert dest.sync_from(source, "absent.bin", "absent.bin") is False


def test_the_source_locker_is_untouched_by_a_sync(pair):
    source, dest = pair
    dest.sync_from(source, "one.bin", "one.bin")

    assert source.file_exists("one.bin") is True


###########################################################
# Batches
###########################################################

def test_a_batch_syncs_every_action(pair):
    source, dest = pair
    succeeded, failed = dest.sync_batch_from(source, [
        {"src": "one.bin", "dest": "one.bin"},
        {"src": "two.bin", "dest": "two.bin"},
    ])

    assert sorted(succeeded) == ["one.bin", "two.bin"]
    assert failed == []


def test_a_batch_reports_failures_separately(pair):
    # One bad entry must not stop the rest of the batch.
    source, dest = pair
    succeeded, failed = dest.sync_batch_from(source, [
        {"src": "one.bin", "dest": "one.bin"},
        {"src": "absent.bin", "dest": "absent.bin"},
        {"src": "two.bin", "dest": "two.bin"},
    ])

    assert sorted(succeeded) == ["one.bin", "two.bin"]
    assert failed == ["absent.bin"]


def test_a_batch_action_without_a_destination_keeps_its_source_name(pair):
    source, dest = pair
    succeeded, failed = dest.sync_batch_from(source, [{"src": "one.bin"}])

    assert succeeded == ["one.bin"]
    assert dest.file_exists("one.bin") is True


def test_an_empty_batch_does_nothing(pair):
    source, dest = pair

    assert dest.sync_batch_from(source, []) == ([], [])


def test_a_batch_reports_destination_names(pair):
    source, dest = pair
    succeeded, failed = dest.sync_batch_from(
        source, [{"src": "one.bin", "dest": "renamed.bin"}])

    assert succeeded == ["renamed.bin"]


###########################################################
# Recycling
###########################################################

def test_a_recycled_file_leaves_its_place(stocked):
    assert stocked.recycle_file("game.zip") is True
    assert stocked.file_exists("game.zip") is False


def test_a_recycled_file_is_kept_in_the_bin(stocked):
    # Recycling is how a delete stays reversible.
    stocked.recycle_file("game.zip")
    bin_root = os.path.join(stocked.get_root_path(), ".recycle_bin")

    assert os.path.exists(bin_root)
    assert any(name == "game.zip" for _, _, files in os.walk(bin_root) for name in files)


def test_a_nested_file_keeps_its_layout_in_the_bin(stocked):
    stocked.recycle_file(os.path.join("docs", "readme.txt"))
    bin_root = os.path.join(stocked.get_root_path(), ".recycle_bin")
    found = [os.path.join(root, name)
             for root, _, files in os.walk(bin_root) for name in files]

    assert any("readme.txt" in path for path in found)


def test_a_custom_recycle_folder_is_used(stocked):
    stocked.recycle_file("game.zip", recycle_folder = ".trash")

    assert os.path.exists(os.path.join(stocked.get_root_path(), ".trash"))


###########################################################
# Backend selection
###########################################################

def test_a_local_only_locker_gets_a_local_backend(tmp_path):
    info = FakeLockerInfo(str(tmp_path), local_only = True)

    assert isinstance(lockerbackend.get_backend_for_locker(info), lockerbackend.LocalBackend)


def test_an_unconfigured_remote_falls_back_to_local(tmp_path, monkeypatch):
    # Without a configured rclone remote there is nothing to talk to, so the
    # mount path is the only thing left that works.
    monkeypatch.setattr(lockerbackend.sync, "is_remote_configured", lambda name, kind: False)
    info = FakeLockerInfo(str(tmp_path), local_only = False, name = "hetzner")

    assert isinstance(lockerbackend.get_backend_for_locker(info), lockerbackend.LocalBackend)


def test_a_configured_remote_gets_a_remote_backend(tmp_path, monkeypatch):
    monkeypatch.setattr(lockerbackend.sync, "is_remote_configured", lambda name, kind: True)
    info = FakeLockerInfo(str(tmp_path), local_only = False, name = "hetzner")

    assert isinstance(lockerbackend.get_backend_for_locker(info), lockerbackend.RemoteBackend)


def test_a_remote_without_a_name_falls_back_to_local(tmp_path, monkeypatch):
    monkeypatch.setattr(lockerbackend.sync, "is_remote_configured", lambda name, kind: True)
    info = FakeLockerInfo(str(tmp_path), local_only = False, name = "")

    assert isinstance(lockerbackend.get_backend_for_locker(info), lockerbackend.LocalBackend)


def test_a_local_backend_reports_no_sidecar_work(locker):
    # Only a remote keeps a sidecar; the local tree is its own index.
    assert locker.update_sidecar_from_local("/anywhere") is True
