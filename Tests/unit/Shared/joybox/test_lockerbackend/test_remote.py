# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, lockerbackend
from lockerbackend_helpers import REMOTE_NAME, REMOTE_PATH, FakeLockerInfo, FakeLocalBackend, backend, called, only


###########################################################
# The remote locker backend
#
# Every operation becomes an rclone call against a named remote. The relative
# path is joined onto the remote root here, so a path that is sent whole, or
# joined twice, addresses somewhere that does not exist.
###########################################################

###########################################################
# Addressing the remote
###########################################################

def test_the_root_is_the_remote_connection_path():
    from joybox import sync

    assert backend().get_root_path() == \
        sync.get_remote_connection_path(REMOTE_NAME, config.RemoteType.SFTP, REMOTE_PATH)


def test_a_remote_without_a_path_uses_its_root():
    assert lockerbackend.RemoteBackend(
        FakeLockerInfo(remote_path = None)).remote_path == ""


def test_a_listing_is_asked_for_with_checksums(remote):
    assert backend().list_files_with_hashes() == {"Game.zip": {"hash": "aaaa"}}
    assert only(remote, "list_files_with_hashes")["hash_type"] == config.HashType.MD5


def test_a_listing_passes_its_excludes(remote):
    backend().list_files_with_hashes(excludes = ["Cache"])

    assert only(remote, "list_files_with_hashes")["excludes"] == ["Cache"]


@pytest.mark.parametrize("method,call", [
    ("file_exists", "does_path_exist"),
    ("path_exists", "does_path_exist"),
    ("path_contains_files", "does_path_contain_files"),
])
def test_an_existence_check_addresses_the_full_remote_path(remote, method, call):
    getattr(backend(), method)("Games/Game.zip")

    assert only(remote, call)["remote_path"] == os.path.join(REMOTE_PATH, "Games/Game.zip")


def test_a_missing_remote_path_is_reported_missing(remote):
    remote["exists"] = False

    assert backend().path_exists("Games/Game.zip") is False


###########################################################
# Uploading
###########################################################

def test_a_file_is_uploaded_into_its_remote_directory(remote, tmp_path):
    # rclone copies a file into a directory, so the destination is the parent
    # rather than the file itself.
    source = tmp_path / "locker"
    (source / "Games").mkdir(parents = True)
    (source / "Games" / "Game.zip").write_text("data")

    assert backend().sync_from(
        FakeLocalBackend(str(source)), "Games/Game.zip", "Games/Game.zip") is True

    passed = only(remote, "upload_files_to_remote")
    assert passed["local_path"] == str(source / "Games" / "Game.zip")
    assert passed["remote_path"] == os.path.join(REMOTE_PATH, "Games")


def test_a_directory_is_uploaded_as_itself(remote, tmp_path):
    # A directory is not copied into its parent; its contents become the
    # destination directory.
    source = tmp_path / "locker"
    (source / "Games").mkdir(parents = True)

    backend().sync_from(FakeLocalBackend(str(source)), "Games", "Games")

    assert only(remote, "upload_files_to_remote")["remote_path"] == \
        os.path.join(REMOTE_PATH, "Games")


def test_an_upload_names_the_remote_it_goes_to(remote, tmp_path):
    source = tmp_path / "locker"
    source.mkdir()
    (source / "Game.zip").write_text("data")

    backend().sync_from(FakeLocalBackend(str(source)), "Game.zip", "Game.zip")

    passed = only(remote, "upload_files_to_remote")
    assert passed["remote_name"] == REMOTE_NAME
    assert passed["remote_type"] == config.RemoteType.SFTP


def test_a_failed_upload_reports_failure(remote, tmp_path):
    source = tmp_path / "locker"
    source.mkdir()
    (source / "Game.zip").write_text("data")
    remote["result"] = False

    assert backend().sync_from(
        FakeLocalBackend(str(source)), "Game.zip", "Game.zip") is False


def test_copying_a_loose_file_in_targets_its_directory(remote):
    assert backend().copy_from("/staging/Game.zip", "Games/Game.zip") is True

    passed = only(remote, "upload_files_to_remote")
    assert passed["local_path"] == "/staging/Game.zip"
    assert passed["remote_path"] == os.path.join(REMOTE_PATH, "Games")


def test_copying_in_a_directory_makes_it_the_destination(remote, tmp_path):
    # rclone copies a directory's contents, so it is aimed at the destination
    # itself rather than its parent.
    source = tmp_path / "Album"
    source.mkdir()

    backend().copy_from(str(source), "Music/Album")

    assert only(remote, "upload_files_to_remote")["remote_path"] == os.path.join(REMOTE_PATH, "Music", "Album")


def test_copying_in_under_a_new_name_keeps_the_new_name(remote, cryption, tmp_path):
    # Callers back up a temporary file under its final name.
    source = tmp_path / "tmp1234.zip"
    source.write_text("data")

    assert backend().copy_from(str(source), "Saves/Game.zip") is True

    passed = only(remote, "upload_files_to_remote")
    assert passed["local_path"] == os.path.join(cryption["scratch"], "Game.zip")
    assert passed["remote_path"] == os.path.join(REMOTE_PATH, "Saves")
    assert cryption["removed"] == [cryption["scratch"]]


def test_copying_in_a_missing_file_under_a_new_name_fails(remote, cryption, tmp_path):
    assert backend().copy_from(str(tmp_path / "absent.zip"), "Saves/Game.zip") is False
    assert remote["calls"] == []
    assert cryption["removed"] == [cryption["scratch"]]


def test_copying_in_under_a_new_name_without_a_scratch_directory_fails(remote, monkeypatch, tmp_path):
    monkeypatch.setattr(
        lockerbackend.fileops, "create_temporary_directory", lambda **kwargs: (False, ""))
    source = tmp_path / "tmp1234.zip"
    source.write_text("data")

    assert backend().copy_from(str(source), "Saves/Game.zip") is False
    assert remote["calls"] == []


def test_copying_in_can_skip_what_is_already_there(remote):
    backend().copy_from("/staging/Game.zip", "Games/Game.zip", skip_existing = True)

    assert only(remote, "upload_files_to_remote")["skip_existing"] is True


###########################################################
# Encrypted uploads
###########################################################

def test_an_encrypted_upload_encrypts_before_it_leaves(remote, cryption, tmp_path):
    # The plaintext must never be handed to rclone.
    source = tmp_path / "locker"
    source.mkdir()
    (source / "Game.zip").write_text("data")

    assert backend().sync_from(
        FakeLocalBackend(str(source)), "Game.zip", "Game.zip",
        cryption_type = config.CryptionType.ENCRYPT, passphrase = "example") is True

    assert cryption["encrypted"][0]["src"] == str(source / "Game.zip")
    assert only(remote, "upload_files_to_remote")["local_path"] == \
        cryption["encrypted"][0]["out"]


def test_an_encrypted_upload_is_staged_under_its_encrypted_name(remote, cryption, tmp_path):
    source = tmp_path / "locker"
    source.mkdir()
    (source / "Game.zip").write_text("data")

    backend().sync_from(
        FakeLocalBackend(str(source)), "Game.zip", "Game.zip",
        cryption_type = config.CryptionType.ENCRYPT, passphrase = "example")

    assert cryption["encrypted"][0]["out"].endswith("Game.zip.enc")


def test_a_failed_encryption_uploads_nothing(remote, cryption, tmp_path):
    source = tmp_path / "locker"
    source.mkdir()
    (source / "Game.zip").write_text("data")
    cryption["result"] = False

    assert backend().sync_from(
        FakeLocalBackend(str(source)), "Game.zip", "Game.zip",
        cryption_type = config.CryptionType.ENCRYPT, passphrase = "example") is False
    assert remote["calls"] == []


def test_the_staged_copy_is_cleaned_up(remote, cryption, tmp_path):
    source = tmp_path / "locker"
    source.mkdir()
    (source / "Game.zip").write_text("data")

    backend().sync_from(
        FakeLocalBackend(str(source)), "Game.zip", "Game.zip",
        cryption_type = config.CryptionType.ENCRYPT, passphrase = "example")

    assert cryption["removed"] == [cryption["scratch"]]


def test_an_upload_without_a_scratch_directory_reports_failure(remote, monkeypatch, tmp_path):
    source = tmp_path / "locker"
    source.mkdir()
    (source / "Game.zip").write_text("data")
    monkeypatch.setattr(
        lockerbackend.fileops, "create_temporary_directory", lambda **kwargs: (False, ""))

    assert backend().sync_from(
        FakeLocalBackend(str(source)), "Game.zip", "Game.zip",
        cryption_type = config.CryptionType.ENCRYPT, passphrase = "example") is False


###########################################################
# Remote to remote
###########################################################

def test_a_plain_remote_to_remote_copy_never_lands_locally(remote):
    # Routing it through this machine would cost the whole file twice over.
    source = lockerbackend.RemoteBackend(FakeLockerInfo(remote_path = "/Other"))

    assert backend().sync_from(source, "Game.zip", "Game.zip") is True

    passed = only(remote, "copy_remote_to_remote")
    assert passed["src_remote_path"] == os.path.join("/Other", "Game.zip")
    assert passed["dest_remote_path"] == os.path.join(REMOTE_PATH, "Game.zip")


def test_a_remote_to_remote_copy_that_fails_reports_failure(remote):
    remote["result"] = False
    source = lockerbackend.RemoteBackend(FakeLockerInfo(remote_path = "/Other"))

    assert backend().sync_from(source, "Game.zip", "Game.zip") is False


def test_a_converting_remote_to_remote_copy_comes_through_this_machine(remote, cryption):
    # There is no way to encrypt in place on the remote, so it is downloaded,
    # converted and uploaded again.
    source = lockerbackend.RemoteBackend(FakeLockerInfo(remote_path = "/Other"))

    backend().sync_from(
        source, "Game.zip", "Game.zip",
        cryption_type = config.CryptionType.ENCRYPT, passphrase = "example")

    assert any(call["name"] == "download_files_from_remote" for call in remote["calls"])
    assert any(call["name"] == "upload_files_to_remote" for call in remote["calls"])


def test_a_failed_download_stops_a_converting_copy(remote, cryption):
    remote["result"] = False
    source = lockerbackend.RemoteBackend(FakeLockerInfo(remote_path = "/Other"))

    assert backend().sync_from(
        source, "Game.zip", "Game.zip",
        cryption_type = config.CryptionType.ENCRYPT, passphrase = "example") is False
    assert not any(call["name"] == "upload_files_to_remote" for call in remote["calls"])


###########################################################
# Recycling on the remote
###########################################################

def test_a_recycled_file_is_named_in_a_file_list(remote):
    # rclone takes the paths to act on from a file rather than the command
    # line, so the list is what decides what gets moved.
    assert backend().recycle_file("Games/Game.zip") is True

    assert only(remote, "recycle_files_on_remote")["files_listed"] == "Games/Game.zip"


def test_a_recycled_file_goes_to_the_recycle_folder(remote):
    backend().recycle_file("Games/Game.zip", recycle_folder = ".bin")

    assert only(remote, "recycle_files_on_remote")["recycle_folder"] == ".bin"


def test_an_encrypted_locker_recycles_the_stored_name(remote, monkeypatch):
    # On an encrypted locker the plaintext name is not what is on the remote,
    # so recycling it would move nothing.
    monkeypatch.setattr(
        lockerbackend.cryption, "generate_encrypted_filename", lambda name: "abc123.enc")

    backend(encrypted = True).recycle_file("Games/Game.zip")

    assert only(remote, "recycle_files_on_remote")["files_listed"] == "Games/abc123.enc"


def test_an_encrypted_locker_recycles_a_top_level_file(remote, monkeypatch):
    monkeypatch.setattr(
        lockerbackend.cryption, "generate_encrypted_filename", lambda name: "abc123.enc")

    backend(encrypted = True).recycle_file("Game.zip")

    assert only(remote, "recycle_files_on_remote")["files_listed"] == "abc123.enc"


def test_a_recycle_without_a_file_list_fails(remote, monkeypatch):
    monkeypatch.setattr(lockerbackend.fileops, "create_temporary_file", lambda **kwargs: (False, None))

    assert backend().recycle_file("Game.zip") is False
    assert remote["calls"] == []


def test_a_file_list_that_cannot_be_written_recycles_nothing(remote, monkeypatch):
    # An empty list would move nothing, or everything.
    monkeypatch.setattr(lockerbackend.serialization, "write_text_file", lambda *args, **kwargs: False)
    removed = []
    monkeypatch.setattr(lockerbackend.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    assert backend().recycle_file("Game.zip") is False
    assert remote["calls"] == []
    assert len(removed) == 1


def test_the_recycle_file_list_is_removed_even_when_recycling_fails(remote):
    remote["result"] = False

    assert backend().recycle_file("Game.zip") is False
    assert not os.path.exists(only(remote, "recycle_files_on_remote")["files_from"])


def test_run_flags_reach_the_recycle(remote):
    backend().recycle_file("Game.zip", verbose = True, pretend_run = True, exit_on_failure = True)

    passed = only(remote, "recycle_files_on_remote")
    assert (passed["verbose"], passed["pretend_run"], passed["exit_on_failure"]) == (True, True, True)


###########################################################
# Refreshing the sidecar
###########################################################

def test_the_sidecar_is_rebuilt_from_local_content(remote):
    assert backend().update_sidecar_from_local("/locker", excludes = ["Cache/**"], pretend_run = True) is True

    passed = only(remote, "upload_hash_sidecar_files")
    assert passed["local_path"] == "/locker"
    assert passed["remote_path"] == REMOTE_PATH
    assert passed["local_root"] == REMOTE_PATH
    assert passed["excludes"] == ["Cache/**"]
    assert passed["pretend_run"] is True
    assert called(remote, "clear_hash_sidecar_files") == []


def test_a_failed_sidecar_rebuild_is_reported(remote):
    remote["result"] = False

    assert backend().update_sidecar_from_local("/locker") is False


def test_a_sidecar_can_be_cleared_before_rebuilding(remote):
    assert backend().update_sidecar_from_local("/locker", clear_first = True) is True

    names = [call["name"] for call in remote["calls"]]
    assert names.index("clear_hash_sidecar_files") < names.index("upload_hash_sidecar_files")


def test_clearing_a_missing_sidecar_is_skipped(remote):
    remote["exists"] = False

    assert backend().update_sidecar_from_local("/locker", clear_first = True) is True
    assert called(remote, "clear_hash_sidecar_files") == []
    assert len(called(remote, "upload_hash_sidecar_files")) == 1


def test_a_sidecar_that_cannot_be_cleared_is_not_rebuilt_on_top_of(remote):
    # Rebuilding over it would keep the stale entries clearing was for.
    remote["results"]["clear_hash_sidecar_files"] = False

    assert backend().update_sidecar_from_local("/locker", clear_first = True) is False
    assert called(remote, "upload_hash_sidecar_files") == []


###########################################################
# Choosing a backend
###########################################################

class LocalOnlyInfo(FakeLockerInfo):

    def is_local_only(self):
        return True

    def get_mount_path(self):
        return "/locker"


def test_a_local_only_locker_gets_the_local_backend():
    assert isinstance(
        lockerbackend.get_backend_for_locker(LocalOnlyInfo()), lockerbackend.LocalBackend)


def test_a_configured_remote_gets_the_remote_backend(monkeypatch):
    monkeypatch.setattr(
        lockerbackend.sync, "is_remote_configured", lambda name, remote_type: True)

    assert isinstance(
        lockerbackend.get_backend_for_locker(FakeLockerInfo()), lockerbackend.RemoteBackend)


def test_an_unconfigured_remote_falls_back_to_local(monkeypatch):
    # Without an rclone remote there is nothing to talk to, and falling back
    # keeps a half-configured machine usable.
    monkeypatch.setattr(
        lockerbackend.sync, "is_remote_configured", lambda name, remote_type: False)

    assert isinstance(
        lockerbackend.get_backend_for_locker(FakeLockerInfo()), lockerbackend.LocalBackend)
