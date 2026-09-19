# Imports
import pytest

# Local imports
from joybox import config, lockerinfo


###########################################################
# Locker info
#
# Every collection path is rooted at the locker mount, and is_encrypted
# decides whether files are encrypted before they leave the machine.
###########################################################

LOCAL = config.LockerType.LOCAL


@pytest.fixture
def local_locker(isolated_settings):
    isolated_settings.set_value("UserData.Share", "locker_local_mount_path", "/locker")
    return isolated_settings


def build(locker_type = LOCAL):
    return lockerinfo.LockerInfo(locker_type)


###########################################################
# Local lockers
###########################################################

def test_the_local_locker_is_the_default(local_locker):
    assert build(None).get_mount_path() == build(LOCAL).get_mount_path()


def test_a_local_locker_has_no_remote_details(local_locker):
    info = build(LOCAL)

    assert info.get_type() is None
    assert info.get_name() is None
    assert info.get_remote_path() is None
    assert info.get_token() is None


def test_a_local_locker_is_local_only(local_locker):
    assert build(LOCAL).is_local_only() is True


def test_a_local_locker_uses_the_local_backend(local_locker):
    assert build(LOCAL).get_backend_type() == config.BackendType.LOCAL


def test_an_external_locker_uses_the_external_backend(isolated_settings):
    assert build(config.LockerType.EXTERNAL).get_backend_type() == \
        config.BackendType.EXTERNAL


def test_the_mount_path_comes_from_settings(local_locker):
    assert build(LOCAL).get_mount_path() == "/locker"


def test_the_root_path_prefers_the_mount_path(local_locker):
    assert build(LOCAL).get_locker_root_path() == "/locker"


def test_the_locker_name_is_the_type(local_locker):
    assert build(LOCAL).get_locker_name() == LOCAL.val()


###########################################################
# Encryption
###########################################################

@pytest.mark.parametrize("value", ["True", "true", "TRUE", "yes", "on", "1"])
def test_every_affirmative_marks_the_locker_encrypted(local_locker, value):
    # Matching only "true" makes any other affirmative read as unencrypted,
    # which fails open on an encryption flag.
    local_locker.set_value("UserData.Share", "locker_local_encrypted", value)

    assert build(LOCAL).is_encrypted() is True


@pytest.mark.parametrize("value", ["False", "false", "no", "off", "0", ""])
def test_every_negative_leaves_the_locker_unencrypted(local_locker, value):
    local_locker.set_value("UserData.Share", "locker_local_encrypted", value)

    assert build(LOCAL).is_encrypted() is False


def test_an_unparseable_flag_is_not_encrypted(local_locker):
    local_locker.set_value("UserData.Share", "locker_local_encrypted", "nonsense")

    assert build(LOCAL).is_encrypted() is False


def test_encryption_defaults_to_off(local_locker):
    assert build(LOCAL).is_encrypted() is False


###########################################################
# Excluded directories
###########################################################

def test_excluded_directories_are_split(local_locker):
    local_locker.set_value("UserData.Share", "locker_local_excluded_dirs", "one,two,three")

    assert build(LOCAL).get_excluded_dirs() == ["one", "two", "three"]


def test_excluded_directories_are_trimmed(local_locker):
    local_locker.set_value("UserData.Share", "locker_local_excluded_dirs", " one , two ")

    assert build(LOCAL).get_excluded_dirs() == ["one", "two"]


def test_empty_entries_are_dropped(local_locker):
    local_locker.set_value("UserData.Share", "locker_local_excluded_dirs", "one,,two,")

    assert build(LOCAL).get_excluded_dirs() == ["one", "two"]


def test_no_excluded_directories_gives_an_empty_list(local_locker):
    local_locker.set_value("UserData.Share", "locker_local_excluded_dirs", "")

    assert build(LOCAL).get_excluded_dirs() == []


###########################################################
# Passphrase
###########################################################

def test_a_locker_passphrase_is_used(local_locker):
    local_locker.set_value("UserData.Share", "locker_local_passphrase", "specific")

    assert build(LOCAL).get_passphrase() == "specific"


def test_the_shared_passphrase_is_the_fallback(local_locker):
    local_locker.set_value("UserData.Share", "locker_local_passphrase", "")
    local_locker.set_value("UserData.Protection", "locker_passphrase", "shared")

    assert build(LOCAL).get_passphrase() == "shared"


def test_a_specific_passphrase_wins_over_the_shared_one(local_locker):
    local_locker.set_value("UserData.Share", "locker_local_passphrase", "specific")
    local_locker.set_value("UserData.Protection", "locker_passphrase", "shared")

    assert build(LOCAL).get_passphrase() == "specific"


###########################################################
# Primary remote
###########################################################

def test_the_configured_primary_remote_is_used(isolated_settings):
    for locker_type in config.LockerType.members():
        if locker_type in (config.LockerType.LOCAL, config.LockerType.EXTERNAL):
            continue
        isolated_settings.set_value("UserData.Share", "primary_remote_locker", locker_type.val())
        assert lockerinfo.get_primary_remote_locker_type() == locker_type
        break


def test_the_primary_remote_lookup_ignores_case(isolated_settings):
    isolated_settings.set_value("UserData.Share", "primary_remote_locker",
                                config.LockerType.HETZNER.val().lower())

    assert lockerinfo.get_primary_remote_locker_type() == config.LockerType.HETZNER


def test_an_unset_primary_remote_falls_back(isolated_settings):
    isolated_settings.set_value("UserData.Share", "primary_remote_locker", "")

    assert lockerinfo.get_primary_remote_locker_type() == config.LockerType.HETZNER


def test_an_unknown_primary_remote_falls_back(isolated_settings):
    isolated_settings.set_value("UserData.Share", "primary_remote_locker", "not-a-locker")

    assert lockerinfo.get_primary_remote_locker_type() == config.LockerType.HETZNER
