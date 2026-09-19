# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, environment


###########################################################
# Directory derivation
#
# Every path in the collection is composed from the locker root, so an extra or
# missing segment here relocates the whole library.
###########################################################

LOCKER_ROOT = "/tmp/joybox-test-locker"


@pytest.fixture
def locker(isolated_settings):
    isolated_settings.set_value("UserData.Share", "locker_local_mount_path", LOCKER_ROOT)
    isolated_settings.set_value("UserData.Dirs", "tools_dir", "/tmp/joybox-test-tools")
    isolated_settings.set_value("UserData.Dirs", "emulators_dir", "/tmp/joybox-test-emulators")
    return isolated_settings


def test_the_locker_root_comes_from_settings(locker):
    assert environment.get_locker_root_dir() == LOCKER_ROOT


def test_the_tools_root_comes_from_settings(locker):
    assert environment.get_tools_root_dir() == "/tmp/joybox-test-tools"


def test_the_emulators_root_comes_from_settings(locker):
    assert environment.get_emulators_root_dir() == "/tmp/joybox-test-emulators"


###########################################################
# Composition
###########################################################

def test_gaming_sits_under_the_locker_root(locker):
    gaming = environment.get_locker_gaming_root_dir()

    assert gaming.startswith(LOCKER_ROOT)
    assert gaming.endswith(str(config.LockerFolderType.GAMING))


def test_development_sits_under_the_locker_root(locker):
    development = environment.get_locker_development_root_dir()

    assert development.startswith(LOCKER_ROOT)
    assert development.endswith(str(config.LockerFolderType.DEVELOPMENT))


def test_archives_sit_under_development(locker):
    assert environment.get_locker_development_archives_root_dir().startswith(
        environment.get_locker_development_root_dir())


@pytest.mark.parametrize("accessor,supercategory", [
    ("get_locker_gaming_roms_root_dir", config.Supercategory.ROMS),
    ("get_locker_gaming_dlc_root_dir", config.Supercategory.DLC),
    ("get_locker_gaming_update_root_dir", config.Supercategory.UPDATES),
    ("get_locker_gaming_tags_root_dir", config.Supercategory.TAGS),
])
def test_each_supercategory_sits_under_gaming(locker, accessor, supercategory):
    derived = getattr(environment, accessor)()

    assert derived.startswith(environment.get_locker_gaming_root_dir())
    assert derived.endswith(str(supercategory))


def test_the_supercategory_directories_are_distinct(locker):
    derived = {
        environment.get_locker_gaming_roms_root_dir(),
        environment.get_locker_gaming_dlc_root_dir(),
        environment.get_locker_gaming_update_root_dir(),
        environment.get_locker_gaming_tags_root_dir(),
    }

    assert len(derived) == 4


def test_derived_paths_are_normalized(locker, isolated_settings):
    # join_paths normalizes, so a trailing separator must not produce a double.
    isolated_settings.set_value("UserData.Share", "locker_local_mount_path", LOCKER_ROOT + "/")

    assert "//" not in environment.get_locker_gaming_roms_root_dir()


def test_changing_the_root_moves_everything(locker, isolated_settings):
    before = environment.get_locker_gaming_roms_root_dir()
    isolated_settings.set_value("UserData.Share", "locker_local_mount_path", "/somewhere/else")
    after = environment.get_locker_gaming_roms_root_dir()

    assert before != after
    assert after.startswith("/somewhere/else")


def test_an_environment_variable_in_the_root_is_expanded(locker, isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_LOCKER", "/expanded/locker")
    isolated_settings.set_value("UserData.Share", "locker_local_mount_path", "$JOYBOX_TEST_LOCKER")

    assert environment.get_locker_root_dir().startswith("/expanded/locker")


def test_the_local_locker_is_the_default(locker):
    assert environment.get_locker_root_dir() == \
        environment.get_locker_root_dir(config.LockerType.LOCAL)
