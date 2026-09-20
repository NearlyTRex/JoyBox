# Third-party imports
import pytest

# Local imports
from joybox import config, sync
from sync_helpers import REMOTE, REMOTE_TYPE, REMOTE_PATH, record


###########################################################
# Listing a remote
#
# rclone distinguishes listing files from listing directories by subcommand,
# and depth by flag. The wrong pair either walks the whole remote or reports
# an empty directory that has contents.
###########################################################

def connection_path():
    return sync.get_remote_connection_path(REMOTE, REMOTE_TYPE, REMOTE_PATH)


def test_files_are_listed_one_level_deep_by_default(rclone, recording_command):
    assert sync.list_files(REMOTE, REMOTE_TYPE, REMOTE_PATH) is True

    assert recording_command.only()[1] == "ls"
    assert recording_command.value_after("--max-depth") == 1


def test_a_recursive_listing_has_no_depth_limit(rclone, recording_command):
    sync.list_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, recursive = True)
    cmd = recording_command.only()

    assert cmd[1] == "ls"
    assert "--max-depth" not in cmd


def test_directories_are_listed_with_their_own_subcommand(rclone, recording_command):
    sync.list_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, only_directories = True)

    assert recording_command.only()[1] == "lsd"


def test_a_recursive_directory_listing_is_marked_recursive(rclone, recording_command):
    sync.list_files(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, only_directories = True, recursive = True)
    cmd = recording_command.only()

    assert cmd[1:3] == ["lsd", "-R"]


def test_a_listing_addresses_the_remote_path(rclone, recording_command):
    sync.list_files(REMOTE, REMOTE_TYPE, REMOTE_PATH)

    assert recording_command.only()[-1] == connection_path()


def test_a_failed_listing_reports_failure(rclone, monkeypatch):
    record(monkeypatch, returncode = 1)

    assert sync.list_files(REMOTE, REMOTE_TYPE, REMOTE_PATH) is False


def test_listing_without_rclone_reports_failure(no_rclone, recording_command):
    assert sync.list_files(REMOTE, REMOTE_TYPE, REMOTE_PATH) is False
    assert recording_command.ran() is False


###########################################################
# Copying between remotes
###########################################################

OTHER = "backblaze"


def test_a_remote_to_remote_copy_names_both_ends(rclone, recording_command):
    assert sync.copy_remote_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH,
        OTHER, REMOTE_TYPE, "/Backup") is True

    cmd = recording_command.only()
    assert cmd[1] == "copyto"
    assert cmd[2] == connection_path()
    assert cmd[3] == sync.get_remote_connection_path(OTHER, REMOTE_TYPE, "/Backup")


def test_a_remote_to_remote_copy_is_a_dry_run_when_pretending(rclone, recording_command):
    # The transfer never touches this machine, so the dry run has to be asked
    # of rclone itself rather than skipped locally.
    sync.copy_remote_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, OTHER, REMOTE_TYPE, "/Backup",
        pretend_run = True)

    assert "--dry-run" in recording_command.only()


def test_a_remote_to_remote_copy_is_not_a_dry_run_by_default(rclone, recording_command):
    sync.copy_remote_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, OTHER, REMOTE_TYPE, "/Backup")

    assert "--dry-run" not in recording_command.only()


def test_a_failed_remote_to_remote_copy_reports_failure(rclone, monkeypatch):
    record(monkeypatch, returncode = 1)

    assert sync.copy_remote_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, OTHER, REMOTE_TYPE, "/Backup") is False


def test_a_remote_to_remote_copy_without_rclone_reports_failure(no_rclone, recording_command):
    assert sync.copy_remote_to_remote(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, OTHER, REMOTE_TYPE, "/Backup") is False
    assert recording_command.ran() is False


###########################################################
# Mounting a remote
###########################################################

@pytest.fixture
def mount_point(tmp_path):
    target = tmp_path / "mount"
    target.mkdir()
    return str(target)


def test_a_remote_is_mounted_at_its_mount_point(rclone, recording_command, mount_point):
    assert sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, mount_point) is True

    cmd = recording_command.only()
    assert cmd[1] == "mount"
    assert cmd[-1] == mount_point or mount_point in cmd


def test_a_mount_caches_by_default(rclone, recording_command, mount_point):
    # Without a cache every read goes back to the remote, which makes reading
    # a game off the mount unusably slow.
    sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, mount_point)

    assert recording_command.value_after("--vfs-cache-mode") == "full"


def test_a_mount_can_skip_the_cache(rclone, recording_command, mount_point):
    sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, mount_point, no_cache = True)

    assert recording_command.value_after("--vfs-cache-mode") == "off"


@pytest.mark.parametrize("option,flag", [
    ("no_checksum", "--no-checksum"),
    ("no_modtime", "--no-modtime"),
    ("no_seek", "--no-seek"),
    ("read_only", "--read-only"),
])
def test_every_mount_option_has_its_flag(rclone, recording_command, mount_point, option, flag):
    sync.mount_files(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, mount_point, **{option: True})

    assert flag in recording_command.only()


@pytest.mark.parametrize("flag", [
    "--no-checksum", "--no-modtime", "--no-seek", "--read-only",
])
def test_no_mount_option_is_added_unasked(rclone, recording_command, mount_point, flag):
    sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, mount_point)

    assert flag not in recording_command.only()


def test_a_mount_point_that_is_already_in_use_is_left_alone(rclone, recording_command, tmp_path):
    # Mounting over a live mount hides whatever is already there.
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "already-here.txt").write_text("data")

    assert sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, str(busy)) is True
    assert recording_command.ran() is False


def test_a_missing_mount_point_is_created(rclone, recording_command, tmp_path, monkeypatch):
    import os

    target = tmp_path / "new-mount"
    monkeypatch.setattr(sync.platform_info, "is_unix_platform", lambda: True)

    assert sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, str(target)) is True
    assert os.path.isdir(str(target))


def test_a_unix_mount_runs_in_the_background(rclone, recording_command, mount_point, monkeypatch):
    # A foreground mount would block the caller for as long as it is mounted.
    monkeypatch.setattr(sync.platform_info, "is_unix_platform", lambda: True)

    sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, mount_point)

    assert "--daemon" in recording_command.only()
    assert recording_command.options().is_daemon() is True


def test_a_failed_mount_reports_failure(rclone, monkeypatch, mount_point):
    record(monkeypatch, returncode = 1)

    assert sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, mount_point) is False


def test_mounting_without_rclone_reports_failure(no_rclone, recording_command, mount_point):
    assert sync.mount_files(REMOTE, REMOTE_TYPE, REMOTE_PATH, mount_point) is False
    assert recording_command.ran() is False


###########################################################
# Listing files with their hashes
#
# This drives the locker comparison, so a file whose hash is read as empty is
# one that looks changed on every run.
###########################################################

LISTING = """[
  {"Path": "Games/Game.zip", "Size": 1024, "ModTime": "2024-01-02T03:04:05Z",
   "IsDir": false, "Hashes": {"MD5": "aaaa", "SHA-1": "bbbb", "SHA-256": "cccc"}},
  {"Path": "Games", "Size": 0, "ModTime": "2024-01-02T03:04:05Z", "IsDir": true,
   "Hashes": {}}
]"""


def hash_listing(monkeypatch, output):
    from fakes import RecordingCommand
    return RecordingCommand(monkeypatch, output = output)


def test_each_file_is_listed_with_its_hash(rclone, monkeypatch):
    hash_listing(monkeypatch, LISTING)

    listed = sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH)

    assert list(listed.keys()) == ["Games/Game.zip"]
    assert listed["Games/Game.zip"]["hash"] == "aaaa"
    assert listed["Games/Game.zip"]["size"] == 1024


def test_a_directory_entry_is_not_listed_as_a_file(rclone, monkeypatch):
    hash_listing(monkeypatch, LISTING)

    assert "Games" not in sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH)


def test_a_listed_file_carries_its_name_and_directory(rclone, monkeypatch):
    hash_listing(monkeypatch, LISTING)

    entry = sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH)["Games/Game.zip"]

    assert entry["filename"] == "Game.zip"
    assert entry["dir"] == "Games"


def test_a_listed_file_carries_a_parsed_time(rclone, monkeypatch):
    hash_listing(monkeypatch, LISTING)

    entry = sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH)["Games/Game.zip"]

    assert entry["mtime"] > 0


@pytest.mark.parametrize("hash_type,expected", [
    (config.HashType.MD5, "aaaa"),
    (config.HashType.SHA1, "bbbb"),
    (config.HashType.SHA256, "cccc"),
])
def test_the_asked_for_hash_is_the_one_returned(rclone, monkeypatch, hash_type, expected):
    # rclone returns every hash the backend knows; taking the wrong one makes
    # every comparison against the local copy fail.
    hash_listing(monkeypatch, LISTING)

    listed = sync.list_files_with_hashes(
        REMOTE, REMOTE_TYPE, REMOTE_PATH, hash_type = hash_type)

    assert listed["Games/Game.zip"]["hash"] == expected


def test_a_lowercase_hash_key_is_accepted(rclone, monkeypatch):
    # Some backends spell the key md5 rather than MD5.
    hash_listing(monkeypatch, """[
      {"Path": "Game.zip", "Size": 1, "ModTime": "2024-01-02T03:04:05Z",
       "IsDir": false, "Hashes": {"md5": "dddd"}}
    ]""")

    listed = sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH)

    assert listed["Game.zip"]["hash"] == "dddd"


def test_a_file_without_a_hash_is_still_listed(rclone, monkeypatch):
    hash_listing(monkeypatch, """[
      {"Path": "Game.zip", "Size": 1, "ModTime": "2024-01-02T03:04:05Z",
       "IsDir": false, "Hashes": {}}
    ]""")

    listed = sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH)

    assert listed["Game.zip"]["hash"] == ""


def test_a_listing_asks_for_hashes_of_files_only(rclone, recording_command):
    sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH)
    cmd = recording_command.only()

    assert cmd[1] == "lsjson"
    assert "--hash" in cmd
    assert "--files-only" in cmd
    assert "--recursive" in cmd


def test_excluded_paths_are_kept_out_of_the_listing(rclone, recording_command):
    sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH, excludes = ["Cache"])

    assert any("Cache" in str(part) for part in recording_command.only())


def test_byte_output_is_decoded_for_a_hash_listing(rclone, monkeypatch):
    hash_listing(monkeypatch, LISTING.encode())

    assert "Games/Game.zip" in sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH)


@pytest.mark.parametrize("output", ["", "   ", "not json at all"])
def test_an_unusable_listing_yields_nothing(rclone, monkeypatch, output):
    hash_listing(monkeypatch, output)

    assert sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH) == {}


def test_a_hash_listing_without_rclone_yields_nothing(no_rclone, recording_command):
    assert sync.list_files_with_hashes(REMOTE, REMOTE_TYPE, REMOTE_PATH) == {}
    assert recording_command.ran() is False
