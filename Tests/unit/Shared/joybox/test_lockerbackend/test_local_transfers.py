# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, lockerbackend
from lockerbackend_helpers import REMOTE_PATH, backend, called, make_locker, only


###########################################################
# Relative paths
#
# Only a path inside the root, matched on whole path parts, is made relative:
# a sibling folder whose name starts with the root's is somewhere else.
###########################################################

def test_a_sibling_that_shares_the_root_prefix_is_left_alone(tmp_path):
    locker = make_locker(tmp_path, {})
    sibling = locker.get_root_path() + "X" + os.sep + "game.zip"

    assert locker.get_relative_path(sibling) == sibling


def test_a_root_with_a_trailing_separator_still_matches(tmp_path):
    locker = make_locker(tmp_path, {})
    root = locker.get_root_path()
    locker.root_path = root + os.sep

    assert locker.get_relative_path(os.path.join(root, "game.zip")) == "game.zip"
    assert locker.get_relative_path(root) == ""


def test_a_locker_without_a_root_leaves_paths_alone(tmp_path):
    locker = make_locker(tmp_path, {})
    locker.root_path = None

    assert locker.get_relative_path("/anywhere/game.zip") == "/anywhere/game.zip"


###########################################################
# Listing
###########################################################

def test_a_dangling_link_is_not_listed(tmp_path):
    locker = make_locker(tmp_path, {"game.zip": "data"})
    os.symlink(str(tmp_path / "absent"), os.path.join(locker.get_root_path(), "dangling"))

    assert list(locker.list_files_with_hashes()) == ["game.zip"]


def test_a_verbose_listing_reports_progress(tmp_path, monkeypatch):
    locker = make_locker(tmp_path, {"file%03d.bin" % index: str(index) for index in range(100)})
    messages = []
    monkeypatch.setattr(lockerbackend.logger, "log_info", lambda message: messages.append(message))
    locker.list_files_with_hashes(verbose = True)

    assert "Processed 100/100 files" in messages


###########################################################
# Converting between local lockers
###########################################################

def test_an_unknown_cryption_type_transfers_nothing(tmp_path, cryption):
    source = make_locker(tmp_path, {"Game.zip": "data"})
    dest = lockerbackend.LocalBackend.__new__(lockerbackend.LocalBackend)
    dest.root_path = str(tmp_path / "dest")

    assert dest.sync_from(source, "Game.zip", "Game.zip", cryption_type = "Rot13") is False
    assert not os.path.exists(dest.root_path)
    assert cryption["encrypted"] == [] and cryption["decrypted"] == []


@pytest.mark.parametrize("cryption_type,done", [
    (config.CryptionType.ENCRYPT, "encrypted"),
    (config.CryptionType.DECRYPT, "decrypted"),
])
def test_a_local_conversion_writes_the_destination(tmp_path, cryption, cryption_type, done):
    source = make_locker(tmp_path, {"Game.zip": "data"})
    dest = lockerbackend.LocalBackend.__new__(lockerbackend.LocalBackend)
    dest.root_path = str(tmp_path / "dest")

    assert dest.sync_from(source, "Game.zip", "Out.zip", cryption_type = cryption_type) is True
    assert cryption[done] == [{
        "src": os.path.join(source.get_root_path(), "Game.zip"),
        "out": os.path.join(dest.root_path, "Out.zip")}]


###########################################################
# Downloading from a remote locker
###########################################################

@pytest.fixture
def dest(tmp_path):
    locker = lockerbackend.LocalBackend.__new__(lockerbackend.LocalBackend)
    locker.root_path = str(tmp_path / "dest")
    return locker


def test_a_download_lands_at_its_destination_path(remote, dest):
    # Aimed at the parent directory, a missing parent would be written as a
    # file named after the directory, and a rename would be lost.
    assert dest.sync_from(backend(), "Games/Game.zip", "Games/Renamed.zip") is True

    passed = only(remote, "download_files_from_remote")
    assert passed["remote_path"] == os.path.join(REMOTE_PATH, "Games/Game.zip")
    assert passed["local_path"] == os.path.join(dest.root_path, "Games", "Renamed.zip")


def test_a_failed_download_reports_failure(remote, dest):
    remote["result"] = False

    assert dest.sync_from(backend(), "Game.zip", "Game.zip") is False


def test_run_flags_reach_the_download(remote, dest):
    dest.sync_from(backend(), "Game.zip", "Game.zip", verbose = True, pretend_run = True, exit_on_failure = True)

    passed = only(remote, "download_files_from_remote")
    assert (passed["verbose"], passed["pretend_run"], passed["exit_on_failure"]) == (True, True, True)


def test_a_download_is_encrypted_on_its_way_in(remote, cryption, dest):
    assert dest.sync_from(
        backend(), "Games/Game.zip", "Games/Game.zip",
        cryption_type = config.CryptionType.ENCRYPT, passphrase = "example") is True

    assert only(remote, "download_files_from_remote")["local_path"] == cryption["scratch"]
    assert cryption["encrypted"] == [{
        "src": os.path.join(cryption["scratch"], "Game.zip"),
        "out": os.path.join(dest.root_path, "Games", "Game.zip")}]
    assert cryption["removed"] == [cryption["scratch"]]


def test_a_decrypted_download_fetches_the_stored_name(remote, cryption, dest):
    # An encrypted locker holds the file under its encrypted name.
    assert dest.sync_from(
        backend(encrypted = True), "Games/Game.zip", "Games/Game.zip",
        cryption_type = config.CryptionType.DECRYPT, passphrase = "example") is True

    assert only(remote, "download_files_from_remote")["remote_path"] == \
        os.path.join(REMOTE_PATH, "Games", "Game.zip.enc")
    assert cryption["decrypted"] == [{
        "src": os.path.join(cryption["scratch"], "Game.zip.enc"),
        "out": os.path.join(dest.root_path, "Games", "Game.zip")}]


def test_a_failed_converting_download_converts_nothing(remote, cryption, dest):
    remote["result"] = False

    assert dest.sync_from(
        backend(), "Game.zip", "Game.zip", cryption_type = config.CryptionType.DECRYPT) is False
    assert cryption["decrypted"] == []
    assert cryption["removed"] == [cryption["scratch"]]


def test_a_failed_conversion_reports_failure(remote, cryption, dest):
    cryption["result"] = False

    assert dest.sync_from(
        backend(), "Game.zip", "Game.zip", cryption_type = config.CryptionType.DECRYPT) is False
    assert cryption["removed"] == [cryption["scratch"]]


def test_a_converting_download_without_a_scratch_directory_fails(remote, dest, monkeypatch):
    monkeypatch.setattr(
        lockerbackend.fileops, "create_temporary_directory", lambda **kwargs: (False, ""))

    assert dest.sync_from(
        backend(), "Game.zip", "Game.zip", cryption_type = config.CryptionType.DECRYPT) is False
    assert called(remote, "download_files_from_remote") == []
