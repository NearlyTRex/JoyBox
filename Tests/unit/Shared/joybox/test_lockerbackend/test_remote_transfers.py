# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, lockerbackend
from lockerbackend_helpers import REMOTE_PATH, FakeLockerInfo, backend, called, make_locker, only


###########################################################
# Listings and stored names
###########################################################

@pytest.mark.parametrize("listing", [None, {}, {"Game.zip": {"hash": "aaaa"}}])
def test_a_sidecar_listing_is_passed_through(remote, listing):
    # None is a failed read and must stay distinct from a remote without hashes.
    remote["listing"] = listing

    assert backend().list_files_with_hashes_from_sidecar(pretend_run = True) == listing
    passed = only(remote, "list_files_with_hashes_from_sidecar")
    assert passed["remote_path"] == REMOTE_PATH
    assert passed["pretend_run"] is True


def test_a_failed_listing_is_passed_through(remote):
    remote["listing"] = None

    assert backend().list_files_with_hashes() is None


def test_a_plain_locker_stores_files_under_their_own_names():
    assert backend().get_stored_rel_path("Games/Game.zip") == "Games/Game.zip"


@pytest.mark.parametrize("rel_path,expected", [
    ("Game.zip", "Game.zip.enc"),
    ("Games/Game.zip", "Games/Game.zip.enc"),
])
def test_an_encrypted_locker_stores_files_under_encrypted_names(cryption, rel_path, expected):
    assert backend(encrypted = True).get_stored_rel_path(rel_path) == expected


###########################################################
# Plain batches
###########################################################

def plain(*names):
    return [{"src": name, "dest": name} for name in names]


def test_a_batch_goes_out_as_one_upload_of_a_file_list(remote, tmp_path):
    source = make_locker(tmp_path, {"One.zip": "1", "Games/Two.zip": "2"})

    result = backend().sync_batch_from(source, plain("One.zip", "Games/Two.zip"))

    assert result == (["One.zip", "Games/Two.zip"], [])
    passed = only(remote, "upload_files_to_remote")
    assert passed["files_listed"] == "One.zip\nGames/Two.zip"
    assert passed["local_path"] == source.get_root_path()
    assert passed["remote_path"] == REMOTE_PATH
    assert passed["update_sidecar"] is False
    assert not os.path.exists(passed["files_from"])


def test_a_failed_batch_upload_fails_every_file(remote, tmp_path):
    remote["result"] = False

    result = backend().sync_batch_from(make_locker(tmp_path, {}), plain("One.zip", "Two.zip"))

    assert result == ([], ["One.zip", "Two.zip"])


def test_a_pretend_batch_uploads_nothing(remote, tmp_path):
    result = backend().sync_batch_from(make_locker(tmp_path, {}), plain("One.zip"), pretend_run = True)

    assert result == (["One.zip"], [])
    assert remote["calls"] == []


def test_a_batch_without_a_file_list_fails(remote, tmp_path, monkeypatch):
    monkeypatch.setattr(lockerbackend.fileops, "create_temporary_file", lambda **kwargs: (False, None))

    result = backend().sync_batch_from(make_locker(tmp_path, {}), plain("One.zip"))

    assert result == ([], ["One.zip"])
    assert remote["calls"] == []


def test_a_file_list_that_cannot_be_written_uploads_nothing(remote, tmp_path, monkeypatch):
    # An empty list would not limit the copy to anything.
    monkeypatch.setattr(lockerbackend.serialization, "write_text_file", lambda *args, **kwargs: False)
    removed = []
    monkeypatch.setattr(lockerbackend.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    result = backend().sync_batch_from(make_locker(tmp_path, {}), plain("One.zip"))

    assert result == ([], ["One.zip"])
    assert remote["calls"] == []
    assert len(removed) == 1


def test_a_renamed_file_in_a_batch_lands_under_its_new_name(remote, cryption, tmp_path):
    # A file list copy keeps source names, so a rename goes on its own.
    source = make_locker(tmp_path, {"One.zip": "1", "Two.zip": "2"})

    result = backend().sync_batch_from(source, [
        {"src": "One.zip", "dest": "One.zip"}, {"src": "Two.zip", "dest": "Games/Renamed.zip"}])

    assert sorted(result[0]) == ["Games/Renamed.zip", "One.zip"]
    uploads = called(remote, "upload_files_to_remote")
    assert uploads[0]["local_path"] == os.path.join(cryption["scratch"], "Renamed.zip")
    assert uploads[0]["remote_path"] == os.path.join(REMOTE_PATH, "Games")
    assert uploads[1]["files_listed"] == "One.zip"


def test_a_batch_of_only_renames_needs_no_file_list(remote, cryption, tmp_path):
    source = make_locker(tmp_path, {"One.zip": "1"})

    result = backend().sync_batch_from(source, [{"src": "One.zip", "dest": "Renamed.zip"}])

    assert result == (["Renamed.zip"], [])
    assert len(called(remote, "upload_files_to_remote")) == 1


def test_an_empty_batch_does_nothing(remote, tmp_path):
    assert backend().sync_batch_from(make_locker(tmp_path, {}), []) == ([], [])
    assert remote["calls"] == []


def test_a_batch_from_another_remote_goes_file_by_file(remote):
    source = lockerbackend.RemoteBackend(FakeLockerInfo(remote_path = "/Other"))

    assert backend().sync_batch_from(source, plain("One.zip", "Two.zip")) == (["One.zip", "Two.zip"], [])
    assert len(called(remote, "copy_remote_to_remote")) == 2


###########################################################
# Encrypted batches
###########################################################

@pytest.fixture
def staging(monkeypatch, tmp_path):
    monkeypatch.setattr(lockerbackend.environment, "get_cache_root_dir", lambda: str(tmp_path / "cache"))


def encrypted_batch(source, actions, **kwargs):
    return backend().sync_batch_from(
        source, actions, cryption_type = config.CryptionType.ENCRYPT, passphrase = "example", **kwargs)


def test_an_encrypted_batch_stages_under_encrypted_names(remote, cryption, staging, tmp_path):
    source = make_locker(tmp_path, {"One.zip": "1", "Games/Two.zip": "2"})

    assert encrypted_batch(source, plain("One.zip", "Games/Two.zip")) == (["One.zip", "Games/Two.zip"], [])
    assert [item["out"] for item in cryption["encrypted"]] == [
        os.path.join(cryption["scratch"], "One.zip.enc"),
        os.path.join(cryption["scratch"], "Games", "Two.zip.enc")]
    passed = only(remote, "upload_files_to_remote")
    assert passed["local_path"] == cryption["scratch"]
    assert passed["update_sidecar"] is False
    assert cryption["removed"] == [cryption["scratch"]]


def test_a_file_that_fails_to_encrypt_is_left_out(remote, cryption, staging, tmp_path):
    cryption["result"] = False

    result = encrypted_batch(make_locker(tmp_path, {"One.zip": "1"}), plain("One.zip"))

    assert result == ([], ["One.zip"])
    assert remote["calls"] == []


def test_a_failed_encrypted_upload_fails_the_staged_files(remote, cryption, staging, tmp_path):
    remote["result"] = False

    assert encrypted_batch(make_locker(tmp_path, {"One.zip": "1"}), plain("One.zip")) == ([], ["One.zip"])


def test_a_missing_source_fails_alone(remote, cryption, staging, tmp_path):
    # It may have gone since the listing; the rest still go out.
    result = encrypted_batch(make_locker(tmp_path, {"One.zip": "1"}), plain("Gone.zip", "One.zip"))

    assert result == (["One.zip"], ["Gone.zip"])


def test_a_batch_whose_sources_are_all_gone_stages_nothing(remote, cryption, staging, tmp_path):
    assert encrypted_batch(make_locker(tmp_path, {}), plain("Gone.zip")) == ([], ["Gone.zip"])
    assert cryption["removed"] == []
    assert remote["calls"] == []


def test_an_encrypted_batch_without_staging_fails(remote, staging, tmp_path, monkeypatch):
    monkeypatch.setattr(lockerbackend.fileops, "create_temporary_directory", lambda **kwargs: (False, None))

    result = encrypted_batch(make_locker(tmp_path, {"One.zip": "1"}), plain("One.zip"))

    assert result == ([], ["One.zip"])
    assert remote["calls"] == []


def test_a_large_delta_is_staged_in_bounded_batches(remote, cryption, staging, tmp_path, monkeypatch):
    # Temp space never has to hold the whole delta at once.
    monkeypatch.setattr(lockerbackend.paths, "get_file_size", lambda path: 3 * 1024 * 1024 * 1024)

    result = encrypted_batch(make_locker(tmp_path, {"One.zip": "1", "Two.zip": "2"}), plain("One.zip", "Two.zip"))

    assert result == (["One.zip", "Two.zip"], [])
    assert len(called(remote, "upload_files_to_remote")) == 2


def test_a_pretend_encrypted_batch_encrypts_nothing(remote, cryption, staging, tmp_path):
    result = encrypted_batch(make_locker(tmp_path, {}), plain("One.zip"), pretend_run = True)

    assert result == (["One.zip"], [])
    assert cryption["encrypted"] == []
    assert remote["calls"] == []


def test_a_decrypting_batch_goes_file_by_file(remote, cryption, tmp_path):
    source = make_locker(tmp_path, {"One.zip": "1", "Two.zip": "2"})

    result = backend().sync_batch_from(
        source, plain("One.zip", "Two.zip"), cryption_type = config.CryptionType.DECRYPT)

    assert result == (["One.zip", "Two.zip"], [])
    assert len(cryption["decrypted"]) == 2


###########################################################
# Single transfers
###########################################################

def test_an_unknown_cryption_type_transfers_nothing(remote, tmp_path):
    source = make_locker(tmp_path, {"Game.zip": "data"})

    assert backend().sync_from(source, "Game.zip", "Game.zip", cryption_type = "Rot13") is False
    assert remote["calls"] == []


def test_a_source_of_another_kind_transfers_nothing(remote):
    assert backend().sync_from(object(), "Game.zip", "Game.zip") is False
    assert remote["calls"] == []


def test_a_renamed_upload_lands_under_its_new_name(remote, cryption, tmp_path):
    source = make_locker(tmp_path, {"Game.zip": "data"})

    assert backend().sync_from(source, "Game.zip", "Games/Renamed.zip") is True

    staged = os.path.join(cryption["scratch"], "Renamed.zip")
    passed = only(remote, "upload_files_to_remote")
    assert passed["local_path"] == staged
    assert passed["remote_path"] == os.path.join(REMOTE_PATH, "Games")
    assert open(staged).read() == "data"


def test_a_renamed_upload_that_cannot_be_staged_fails(remote, cryption, tmp_path):
    source = make_locker(tmp_path, {})

    assert backend().sync_from(source, "Gone.zip", "Renamed.zip") is False
    assert called(remote, "upload_files_to_remote") == []


def test_a_decrypted_upload_is_named_for_its_destination(remote, cryption, tmp_path):
    source = make_locker(tmp_path, {"Games/abc123.enc": "secret"})

    assert backend().sync_from(
        source, "Games/abc123.enc", "Games/Game.zip",
        cryption_type = config.CryptionType.DECRYPT, passphrase = "example") is True

    assert cryption["decrypted"][0]["out"] == os.path.join(cryption["scratch"], "staged", "Game.zip")
    assert only(remote, "upload_files_to_remote")["remote_path"] == os.path.join(REMOTE_PATH, "Games")


def test_run_flags_reach_a_single_upload(remote, tmp_path):
    source = make_locker(tmp_path, {"Game.zip": "data"})
    backend().sync_from(source, "Game.zip", "Game.zip", verbose = True, pretend_run = True, exit_on_failure = True)

    passed = only(remote, "upload_files_to_remote")
    assert (passed["verbose"], passed["pretend_run"], passed["exit_on_failure"]) == (True, True, True)


def test_a_remote_to_remote_encryption_uses_the_destination_name(remote, cryption):
    # Named from the scratch path, the stored name would never be found again.
    source = lockerbackend.RemoteBackend(FakeLockerInfo(remote_path = "/Other"))

    assert backend().sync_from(
        source, "Games/Game.zip", "Games/Game.zip",
        cryption_type = config.CryptionType.ENCRYPT, passphrase = "example") is True

    download = only(remote, "download_files_from_remote")
    assert download["remote_path"] == os.path.join("/Other", "Games", "Game.zip")
    assert cryption["encrypted"] == [{
        "src": os.path.join(cryption["scratch"], "download", "Game.zip"),
        "out": os.path.join(cryption["scratch"], "staged", "Game.zip.enc")}]
    upload = only(remote, "upload_files_to_remote")
    assert upload["local_path"] == os.path.join(cryption["scratch"], "staged", "Game.zip.enc")
    assert upload["remote_path"] == os.path.join(REMOTE_PATH, "Games")


def test_a_remote_to_remote_decryption_keeps_the_plain_name(remote, cryption):
    # The upload keeps the staged file's name, so it must be the destination's.
    source = lockerbackend.RemoteBackend(FakeLockerInfo(encrypted = True, remote_path = "/Other"))

    assert backend().sync_from(
        source, "Games/Game.zip", "Games/Game.zip",
        cryption_type = config.CryptionType.DECRYPT, passphrase = "example") is True

    assert only(remote, "download_files_from_remote")["remote_path"] == \
        os.path.join("/Other", "Games", "Game.zip.enc")
    assert cryption["decrypted"][0]["out"] == os.path.join(cryption["scratch"], "staged", "Game.zip")
    assert only(remote, "upload_files_to_remote")["local_path"] == \
        os.path.join(cryption["scratch"], "staged", "Game.zip")


def test_a_failed_remote_to_remote_conversion_uploads_nothing(remote, cryption):
    cryption["result"] = False
    source = lockerbackend.RemoteBackend(FakeLockerInfo(remote_path = "/Other"))

    assert backend().sync_from(
        source, "Game.zip", "Game.zip", cryption_type = config.CryptionType.DECRYPT) is False
    assert called(remote, "upload_files_to_remote") == []
    assert cryption["removed"] == [cryption["scratch"]]
