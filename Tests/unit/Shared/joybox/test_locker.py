# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, locker


###########################################################
# Locker paths
#
# Decides whether a file is reached on disk or through a remote backend, so a
# misclassified path either silently skips a download or tries to read a
# remote file locally.
###########################################################

LOCAL_ROOT = "/locker"
REMOTE_ROOT = "/remote"
REMOTE = config.LockerType.HETZNER


@pytest.fixture
def lockers(isolated_settings):
    isolated_settings.set_value("UserData.Share", "locker_local_mount_path", LOCAL_ROOT)
    isolated_settings.set_value("UserData.Share", f"locker_{REMOTE.lower()}_mount_path", REMOTE_ROOT)
    isolated_settings.set_value("UserData.Share", "primary_remote_locker", REMOTE.val())

    # A locker with no remote type reads as local only, which routes around
    # every remote code path including encryption.
    isolated_settings.set_value("UserData.Share", f"locker_{REMOTE.lower()}_type", "sftp")
    isolated_settings.set_value("UserData.Share", f"locker_{REMOTE.lower()}_name", "hetzner")
    return isolated_settings


###########################################################
# Classification
###########################################################

def test_a_path_under_the_local_root_is_local(lockers):
    assert locker.is_local_path(f"{LOCAL_ROOT}/Gaming/game.z64") is True


def test_a_path_under_a_remote_root_is_not_local(lockers):
    assert locker.is_local_path(f"{REMOTE_ROOT}/Gaming/game.z64") is False


def test_a_path_that_exists_on_disk_is_local(lockers, tmp_path):
    # Anything actually present is reachable without a backend.
    assert locker.is_local_path(str(tmp_path)) is True


def test_remote_is_the_complement_of_local(lockers):
    for path in [f"{LOCAL_ROOT}/x", f"{REMOTE_ROOT}/x", "/nowhere/x"]:
        assert locker.is_remote_path(path) is (not locker.is_local_path(path))


def test_the_local_root_itself_is_not_matched_as_a_prefix(lockers):
    # "/lockerother" must not count as being under "/locker".
    assert locker.is_local_path("/lockerother/game.z64") is False


###########################################################
# Relative paths
###########################################################

def test_the_local_root_is_stripped(lockers):
    assert locker.convert_to_relative_path(f"{LOCAL_ROOT}/Gaming/Roms/game.z64") == \
        os.path.join("Gaming", "Roms", "game.z64")


def test_a_remote_root_is_stripped_for_its_own_locker(lockers):
    assert locker.convert_to_relative_path(f"{REMOTE_ROOT}/Gaming/game.z64", REMOTE) == \
        os.path.join("Gaming", "game.z64")


def test_a_path_outside_the_root_is_left_alone(lockers):
    assert locker.convert_to_relative_path("/elsewhere/game.z64") == \
        os.path.normpath("/elsewhere/game.z64")


###########################################################
# Localizing
###########################################################

def test_a_remote_path_is_rebased_onto_the_local_root(lockers):
    assert locker.convert_to_local_path(f"{REMOTE_ROOT}/Gaming/game.z64", REMOTE) == \
        os.path.normpath(f"{LOCAL_ROOT}/Gaming/game.z64")


def test_an_already_local_path_is_returned_unchanged(lockers):
    original = f"{LOCAL_ROOT}/Gaming/game.z64"

    assert locker.convert_to_local_path(original) == original


def test_the_default_source_is_the_primary_remote(lockers):
    assert locker.convert_to_local_path(f"{REMOTE_ROOT}/Gaming/game.z64") == \
        os.path.normpath(f"{LOCAL_ROOT}/Gaming/game.z64")


def test_localizing_preserves_the_relative_position(lockers):
    # The path below the root has to survive the move between lockers.
    remote = f"{REMOTE_ROOT}/Gaming/Roms/Nintendo/game.z64"
    localized = locker.convert_to_local_path(remote, REMOTE)

    assert locker.convert_to_relative_path(localized) == \
        locker.convert_to_relative_path(remote, REMOTE)


###########################################################
# Default remote
###########################################################

def test_the_default_remote_follows_the_setting(lockers):
    assert locker.get_default_remote_locker() == REMOTE


def test_the_default_remote_is_never_the_local_locker(lockers):
    assert locker.get_default_remote_locker() != config.LockerType.LOCAL


###########################################################
# Locker backends
#
# Every transfer goes through a backend pair rather than touching the remote
# directly. What matters is which backend is asked, and with which relative
# path - a full path handed to a backend lands outside the locker root.
###########################################################

class FakeBackend:

    def __init__(self, root = "/locker", exists = True, contains_files = True, result = True):
        self.root = root
        self.exists = exists
        self.contains_files = contains_files
        self.result = result
        self.synced = []
        self.copied = []

    def get_root_path(self):
        return self.root

    def get_relative_path(self, full_path):
        if full_path.startswith(self.root + "/"):
            return full_path[len(self.root) + 1:]
        return full_path

    def path_exists(self, rel_path):
        return self.exists

    def path_contains_files(self, rel_path):
        return self.contains_files

    def sync_from(self, src_backend, src_rel_path, dest_rel_path, **kwargs):
        self.synced.append({
            "src_backend": src_backend,
            "src": src_rel_path,
            "dest": dest_rel_path,
        })
        return self.result

    def copy_from(self, src_abs_path, dest_rel_path, **kwargs):
        self.copied.append({"src": src_abs_path, "dest": dest_rel_path, "options": kwargs})
        return self.result


@pytest.fixture
def backends(lockers, monkeypatch):
    # One backend per locker type, so a test can tell which end was used.
    made = {}

    def get_backend_for_locker(locker_info):
        name = locker_info.get_locker_name()
        if name not in made:
            root = LOCAL_ROOT if name == config.LockerType.LOCAL.val() else REMOTE_ROOT
            made[name] = FakeBackend(root = root)
        return made[name]

    monkeypatch.setattr(locker.lockerbackend, "get_backend_for_locker", get_backend_for_locker)
    return made


def backend_for(backends, locker_type):
    # The backends are made on demand, so a test that asserts on one that was
    # never reached would otherwise fail on a missing key rather than on what
    # it meant to check.
    name = locker_type.val()
    if name not in backends:
        backends[name] = FakeBackend(
            root = LOCAL_ROOT if locker_type == config.LockerType.LOCAL else REMOTE_ROOT)
    return backends[name]


def local_backend(backends):
    return backend_for(backends, config.LockerType.LOCAL)


def remote_backend(backends):
    return backend_for(backends, REMOTE)


###########################################################
# Asking the backend about a path
###########################################################

def test_a_path_is_looked_up_on_the_remote_backend(backends):
    assert locker.does_path_exist("/remote/Games/Game.zip") is True


def test_a_missing_path_is_reported_missing(backends):
    remote_backend(backends).exists = False

    assert locker.does_path_exist("/remote/Games/Game.zip") is False


def test_a_populated_path_is_recognised(backends):
    assert locker.does_path_contain_files("/remote/Games") is True


def test_an_empty_path_is_recognised(backends):
    remote_backend(backends).contains_files = False

    assert locker.does_path_contain_files("/remote/Games") is False


###########################################################
# Syncing between lockers
###########################################################

def test_a_download_pulls_from_the_remote_into_the_local_locker(backends):
    success, path = locker.sync_from_remote("/remote/Games/Game.zip")

    assert success is True
    assert path == os.path.join(LOCAL_ROOT, "Games/Game.zip")


def test_a_download_asks_the_local_backend_to_pull(backends):
    # The destination backend drives the transfer, so a download recorded on
    # the remote backend would be an upload.
    locker.sync_from_remote("/remote/Games/Game.zip")

    assert local_backend(backends).synced[0]["src_backend"] is remote_backend(backends)
    assert remote_backend(backends).synced == []


def test_a_download_keeps_the_relative_path(backends):
    locker.sync_from_remote("/remote/Games/Game.zip")
    transfer = local_backend(backends).synced[0]

    assert transfer["src"] == "Games/Game.zip"
    assert transfer["dest"] == "Games/Game.zip"


def test_a_download_can_be_redirected(backends):
    locker.sync_from_remote("/remote/Games/Game.zip", dest = "/locker/Staging/Game.zip")

    assert local_backend(backends).synced[0]["dest"] == "Staging/Game.zip"


def test_a_failed_download_reports_no_path(backends):
    local_backend(backends).result = False

    assert locker.sync_from_remote("/remote/Games/Game.zip") == (False, "")


def test_an_upload_pushes_from_the_local_locker_to_the_remote(backends, tmp_path):
    source = tmp_path / "Game.zip"
    source.write_text("data")

    assert locker.sync_to_remote(str(source)) is True
    assert remote_backend(backends).synced[0]["src_backend"] is local_backend(backends)


def test_an_upload_of_a_missing_source_is_refused(backends, tmp_path):
    assert locker.sync_to_remote(str(tmp_path / "absent.zip")) is False
    assert remote_backend(backends).synced == []


def test_an_upload_can_be_redirected(backends, tmp_path):
    source = tmp_path / "Game.zip"
    source.write_text("data")

    locker.sync_to_remote(str(source), dest = "/remote/Staging/Game.zip")

    assert remote_backend(backends).synced[0]["dest"] == "Staging/Game.zip"


###########################################################
# Copying into a locker
###########################################################

def test_a_file_is_copied_to_the_locker_it_was_given(backends, tmp_path):
    source = tmp_path / "Game.zip"
    source.write_text("data")

    assert locker.copy_to_locker(str(source), "Games/Game.zip", REMOTE) is True
    assert remote_backend(backends).copied[0]["dest"] == "Games/Game.zip"


def test_copying_a_missing_source_is_refused(backends, tmp_path):
    assert locker.copy_to_locker(str(tmp_path / "absent.zip"), "Games/Game.zip", REMOTE) is False
    assert remote_backend(backends).copied == []


@pytest.mark.parametrize("option", ["skip_existing", "skip_identical", "show_progress"])
def test_every_copy_option_reaches_the_backend(backends, tmp_path, option):
    source = tmp_path / "Game.zip"
    source.write_text("data")

    locker.copy_to_locker(str(source), "Games/Game.zip", REMOTE, **{option: True})

    assert remote_backend(backends).copied[0]["options"][option] is True


###########################################################
# Encrypted uploads
###########################################################

@pytest.fixture
def encryption(monkeypatch, tmp_path):
    # Records what would have been encrypted, and where the staged file went.
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    state = {"encrypted": [], "passphrase": "secret-phrase", "result": True,
             "scratch": str(scratch), "removed": []}

    monkeypatch.setattr(
        locker.fileops, "create_temporary_directory",
        lambda **kwargs: (True, str(scratch)))
    monkeypatch.setattr(
        locker.fileops, "remove_directory",
        lambda src, **kwargs: state["removed"].append(src))

    def encrypt_file(src, passphrase, output_file, **kwargs):
        state["encrypted"].append({"src": src, "passphrase": passphrase, "out": output_file})
        if state["result"]:
            with open(output_file, "w") as handle:
                handle.write("encrypted")
        return state["result"]

    monkeypatch.setattr(locker.cryption, "encrypt_file", encrypt_file)
    monkeypatch.setattr(
        locker.lockerinfo.LockerInfo, "get_passphrase", lambda self: state["passphrase"])
    return state


def test_an_encrypted_upload_encrypts_before_it_copies(backends, encryption, tmp_path):
    # The plaintext must never reach the remote, so the copy takes the staged
    # encrypted file rather than the source.
    source = tmp_path / "Game.zip"
    source.write_text("data")

    assert locker.copy_to_locker_encrypted(str(source), "Games/Game.zip", REMOTE) is True

    assert encryption["encrypted"][0]["src"] == str(source)
    assert remote_backend(backends).copied[0]["src"] == encryption["encrypted"][0]["out"]


def test_an_encrypted_upload_is_named_as_encrypted(backends, encryption, tmp_path):
    source = tmp_path / "Game.zip"
    source.write_text("data")

    locker.copy_to_locker_encrypted(str(source), "Games/Game.zip", REMOTE)

    assert remote_backend(backends).copied[0]["dest"] == "Games/Game.zip.enc"


def test_the_staged_encrypted_file_is_cleaned_up(backends, encryption, tmp_path):
    source = tmp_path / "Game.zip"
    source.write_text("data")

    locker.copy_to_locker_encrypted(str(source), "Games/Game.zip", REMOTE)

    assert encryption["removed"] == [encryption["scratch"]]


def test_a_failed_encryption_uploads_nothing(backends, encryption, tmp_path):
    source = tmp_path / "Game.zip"
    source.write_text("data")
    encryption["result"] = False

    assert locker.copy_to_locker_encrypted(str(source), "Games/Game.zip", REMOTE) is False
    assert remote_backend(backends).copied == []


def test_a_locker_without_a_passphrase_uploads_unencrypted(backends, encryption, tmp_path):
    # Refusing to upload would silently skip the backup; the warning and a
    # plain upload is the documented fallback.
    source = tmp_path / "Game.zip"
    source.write_text("data")
    encryption["passphrase"] = None

    assert locker.copy_to_locker_encrypted(str(source), "Games/Game.zip", REMOTE) is True
    assert remote_backend(backends).copied[0]["dest"] == "Games/Game.zip"


def test_an_unusable_scratch_directory_uploads_nothing(backends, encryption, monkeypatch, tmp_path):
    source = tmp_path / "Game.zip"
    source.write_text("data")
    monkeypatch.setattr(
        locker.fileops, "create_temporary_directory", lambda **kwargs: (False, ""))

    assert locker.copy_to_locker_encrypted(str(source), "Games/Game.zip", REMOTE) is False
    assert remote_backend(backends).copied == []


###########################################################
# Backing up
###########################################################

def test_a_backup_copies_to_the_locker_it_was_given(backends, tmp_path):
    source = tmp_path / "Game.zip"
    source.write_text("data")

    assert locker.backup(str(source), "Games/Game.zip", locker_type = REMOTE) is True
    assert remote_backend(backends).copied[0]["dest"] == "Games/Game.zip"


def test_a_backup_of_a_missing_source_is_refused(backends, tmp_path):
    assert locker.backup(str(tmp_path / "absent.zip"), "Games/Game.zip", locker_type = REMOTE) is False


def test_no_locker_means_no_backup(backends, tmp_path):
    # Most callers pass the locker through from a setting that may be unset,
    # and that is not an error.
    source = tmp_path / "Game.zip"
    source.write_text("data")

    assert locker.backup(str(source), "Games/Game.zip") is True
    assert remote_backend(backends).copied == []


def test_a_backup_to_every_locker_uses_each_configured_one(backends, monkeypatch, tmp_path):
    source = tmp_path / "Game.zip"
    source.write_text("data")
    monkeypatch.setattr(
        locker, "get_configured_lockers", lambda: [config.LockerType.LOCAL, REMOTE])

    assert locker.backup(str(source), "Games/Game.zip", locker_type = config.LockerType.ALL) is True
    assert len(local_backend(backends).copied) == 1
    assert len(remote_backend(backends).copied) == 1


def test_a_backup_to_every_locker_with_none_configured_is_not_a_failure(backends, monkeypatch, tmp_path):
    source = tmp_path / "Game.zip"
    source.write_text("data")
    monkeypatch.setattr(locker, "get_configured_lockers", lambda: [])

    assert locker.backup(str(source), "Games/Game.zip", locker_type = config.LockerType.ALL) is True


def test_one_failed_locker_does_not_stop_the_others(backends, monkeypatch, tmp_path):
    # A remote that is down should not cost the backup to the local disk.
    source = tmp_path / "Game.zip"
    source.write_text("data")
    monkeypatch.setattr(
        locker, "get_configured_lockers", lambda: [config.LockerType.LOCAL, REMOTE])
    remote_backend(backends).result = False

    assert locker.backup(str(source), "Games/Game.zip", locker_type = config.LockerType.ALL) is False
    assert len(local_backend(backends).copied) == 1


def test_a_backup_can_remove_the_source_afterwards(backends, monkeypatch, tmp_path):
    # The source is usually a staged copy that costs disk space, and this is
    # the only thing that cleans it up.
    source = tmp_path / "Game.zip"
    source.write_text("data")
    removed = []
    monkeypatch.setattr(
        locker.fileops, "remove_file_or_directory",
        lambda src, **kwargs: removed.append(src))

    assert locker.backup(
        str(source), "Games/Game.zip", locker_type = REMOTE, delete_afterwards = True) is True
    assert removed == [str(source)]


def test_a_failed_backup_keeps_the_source(backends, monkeypatch, tmp_path):
    source = tmp_path / "Game.zip"
    source.write_text("data")

    def fail(*args, **kwargs):
        raise AssertionError("the source must survive a failed backup")

    monkeypatch.setattr(locker.fileops, "remove_file_or_directory", fail)
    remote_backend(backends).result = False

    assert locker.backup(
        str(source), "Games/Game.zip", locker_type = REMOTE, delete_afterwards = True) is False


def test_a_backup_can_be_encrypted(backends, encryption, tmp_path):
    source = tmp_path / "Game.zip"
    source.write_text("data")

    locker.backup(
        str(source), "Games/Game.zip", locker_type = REMOTE, upload_encrypted = True)

    assert remote_backend(backends).copied[0]["dest"] == "Games/Game.zip.enc"
