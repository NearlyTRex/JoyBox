# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, lockerbackend


###########################################################
# The remote locker backend
#
# Every operation becomes an rclone call against a named remote. The relative
# path is joined onto the remote root here, so a path that is sent whole, or
# joined twice, addresses somewhere that does not exist.
###########################################################

REMOTE_NAME = "hetzner"
REMOTE_PATH = "/Locker"


class FakeLockerInfo:

    def __init__(self, encrypted = False, remote_path = REMOTE_PATH, passphrase = None):
        self.encrypted = encrypted
        self.remote_path = remote_path
        self.passphrase = passphrase

    def get_name(self):
        return REMOTE_NAME

    def get_type(self):
        return config.RemoteType.SFTP

    def get_remote_path(self):
        return self.remote_path

    def get_mount_path(self):
        return None

    def is_encrypted(self):
        return self.encrypted

    def is_local_only(self):
        return False

    def get_passphrase(self):
        return self.passphrase


class FakeLocalBackend(lockerbackend.LocalBackend):

    def __init__(self, root):
        self.root_path = root
        self.locker_info = None


@pytest.fixture
def remote(monkeypatch):
    # Records what would have been asked of rclone.
    state = {"calls": [], "result": True, "exists": True, "contains": True,
             "listing": {"Game.zip": {"hash": "aaaa"}}}

    def record(name, result_key = "result"):
        def run(**kwargs):
            # The file list is a temporary file the caller deletes afterwards,
            # so its contents are read while the call is still in progress.
            if kwargs.get("files_from") and os.path.isfile(kwargs["files_from"]):
                with open(kwargs["files_from"]) as handle:
                    kwargs = dict(kwargs, files_listed = handle.read().strip())
            state["calls"].append({"name": name, "kwargs": kwargs})
            if result_key == "listing":
                return state["listing"]
            if result_key == "exists":
                return state["exists"]
            if result_key == "contains":
                return state["contains"]
            return state["result"]
        return run

    for name, key in [
        ("upload_files_to_remote", "result"),
        ("download_files_from_remote", "result"),
        ("copy_remote_to_remote", "result"),
        ("recycle_files_on_remote", "result"),
        ("list_files_with_hashes", "listing"),
        ("does_path_exist", "exists"),
        ("does_path_contain_files", "contains"),
    ]:
        monkeypatch.setattr(lockerbackend.sync, name, record(name, key))
    return state


def only(state, name):
    matching = [call for call in state["calls"] if call["name"] == name]
    assert len(matching) == 1, "expected one %s call, recorded %d" % (name, len(matching))
    return matching[0]["kwargs"]


def backend(**kwargs):
    return lockerbackend.RemoteBackend(FakeLockerInfo(**kwargs))


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


def test_copying_in_can_skip_what_is_already_there(remote):
    backend().copy_from("/staging/Game.zip", "Games/Game.zip", skip_existing = True)

    assert only(remote, "upload_files_to_remote")["skip_existing"] is True


###########################################################
# Encrypted uploads
###########################################################

@pytest.fixture
def cryption(monkeypatch, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    state = {"encrypted": [], "decrypted": [], "result": True, "scratch": str(scratch),
             "removed": []}

    monkeypatch.setattr(
        lockerbackend.fileops, "create_temporary_directory",
        lambda **kwargs: (True, str(scratch)))
    monkeypatch.setattr(
        lockerbackend.fileops, "remove_directory",
        lambda src, **kwargs: state["removed"].append(src))
    monkeypatch.setattr(
        lockerbackend.cryption, "generate_encrypted_filename", lambda name: name + ".enc")

    def encrypt_file(src, passphrase, output_file, **kwargs):
        state["encrypted"].append({"src": src, "out": output_file})
        return state["result"]

    def decrypt_file(src, passphrase, output_file, **kwargs):
        state["decrypted"].append({"src": src, "out": output_file})
        return state["result"]

    monkeypatch.setattr(lockerbackend.cryption, "encrypt_file", encrypt_file)
    monkeypatch.setattr(lockerbackend.cryption, "decrypt_file", decrypt_file)
    return state


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
