# Third-party imports
import pytest

# Local imports
from joybox import config, sync
from sync_helpers import REMOTE, REMOTE_TYPE


###########################################################
# Flags
###########################################################

def base_flags():
    return sync.get_common_remote_flags("Remote", config.RemoteType.SFTP, None)


def test_the_common_flags_are_always_present():
    flags = base_flags()

    for flag in ["--fast-list", "--tpslimit", "--transfers", "--order-by"]:
        assert flag in flags


def test_transfers_are_serialized():
    # Concurrent transfers to the storage box have caused throttling.
    flags = base_flags()

    assert flags[flags.index("--transfers") + 1] == "1"


@pytest.mark.parametrize("action_type", config.RemoteActionSyncType.members())
def test_a_sync_action_tracks_renames(action_type):
    flags = sync.get_common_remote_flags("Remote", config.RemoteType.SFTP, action_type)

    assert "--track-renames" in flags


@pytest.mark.parametrize("action_type", config.RemoteActionChangeType.members())
def test_a_change_action_creates_empty_directories(action_type):
    flags = sync.get_common_remote_flags("Remote", config.RemoteType.SFTP, action_type)

    assert "--create-empty-src-dirs" in flags


def test_a_drive_remote_gets_its_own_flags():
    flags = sync.get_common_remote_flags("Remote", config.RemoteType.DRIVE, None)

    for flag in ["--drive-acknowledge-abuse", "--drive-stop-on-upload-limit",
                 "--drive-stop-on-download-limit", "--drive-chunk-size"]:
        assert flag in flags


def test_a_non_drive_remote_gets_no_drive_flags():
    flags = sync.get_common_remote_flags("Remote", config.RemoteType.SFTP, None)

    assert not any(flag.startswith("--drive-") for flag in flags)


###########################################################
# Excludes
###########################################################

def test_empty_excludes_produce_no_flags():
    assert sync.get_exclude_flags([]) == []
    assert sync.get_exclude_flags("") == []
    assert sync.get_exclude_flags(None) == []


def test_blank_entries_are_skipped():
    # A bare "--exclude" with no pattern would consume the next argument.
    assert sync.get_exclude_flags(["one", "", "two"]) == \
        ["--exclude", "one", "--exclude", "two"]


def test_exclude_flags_stay_paired():
    flags = sync.get_exclude_flags(["a", "b", "c"])

    assert len(flags) % 2 == 0
    assert flags[::2] == ["--exclude"] * 3


###########################################################
# Rclone invocation
#
# Every remote operation is an rclone command. A wrong flag or a swapped
# source and destination moves or deletes the wrong side of the sync, and the
# tool reports success either way.
###########################################################




###########################################################
# Common flags
###########################################################

def flags_for(action_type = None, remote_type = None):
    return sync.get_common_remote_flags(
        REMOTE, remote_type or REMOTE_TYPE, action_type)


def test_transfers_stay_serial():
    # Parallel transfers to the storage box trip its connection limit.
    built = flags_for()

    assert built[built.index("--transfers") + 1] == "1"


def test_requests_are_rate_limited():
    built = flags_for()

    assert built[built.index("--tpslimit") + 1] == "10"


def test_smallest_files_go_first():
    # So an interrupted run has moved as many whole files as possible.
    built = flags_for()

    assert built[built.index("--order-by") + 1] == "size,ascending"


def test_listing_is_batched():
    assert "--fast-list" in flags_for()


@pytest.mark.parametrize("action_type", config.RemoteActionSyncType.members())
def test_a_sync_tracks_renames(action_type):
    # Without this a renamed file is re-uploaded in full.
    assert "--track-renames" in flags_for(action_type)


@pytest.mark.parametrize("action_type", config.RemoteActionChangeType.members())
def test_a_change_keeps_empty_directories(action_type):
    assert "--create-empty-src-dirs" in flags_for(action_type)


def test_a_plain_action_adds_neither():
    built = flags_for()

    assert "--track-renames" not in built
    assert "--create-empty-src-dirs" not in built


def test_google_drive_gets_its_own_flags():
    built = flags_for(remote_type = config.RemoteType.DRIVE)

    assert "--drive-acknowledge-abuse" in built
    assert "--drive-stop-on-upload-limit" in built
    assert "--drive-stop-on-download-limit" in built
    assert built[built.index("--drive-chunk-size") + 1] == "256M"


def test_another_remote_gets_no_drive_flags():
    built = flags_for(remote_type = config.RemoteType.B2)

    assert not any(flag.startswith("--drive") for flag in built)


###########################################################
# Exclude flags
###########################################################

def test_each_exclude_becomes_a_flag_pair():
    assert sync.get_exclude_flags(["*.tmp", "cache/**"]) == \
        ["--exclude", "*.tmp", "--exclude", "cache/**"]


def test_a_single_exclude_string_is_accepted():
    assert sync.get_exclude_flags("*.tmp") == ["--exclude", "*.tmp"]


def test_a_blank_exclude_is_dropped():
    # A bare --exclude would swallow the next argument as its pattern.
    assert sync.get_exclude_flags(["", "*.tmp", ""]) == ["--exclude", "*.tmp"]


@pytest.mark.parametrize("value", [[], "", None, 12345])
def test_nothing_to_exclude_adds_no_flags(value):
    assert sync.get_exclude_flags(value) == []


