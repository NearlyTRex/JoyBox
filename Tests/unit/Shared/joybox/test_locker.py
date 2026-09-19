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
