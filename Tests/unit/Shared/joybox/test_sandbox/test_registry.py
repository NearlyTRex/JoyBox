# Imports
import os

# Third-party imports
import pytest

# Local imports
import joybox.registry as registry
from joybox import config, sandbox
from sandbox_helpers import WINE


###########################################################
# Registry backup and restore
#
# Setup and game prefixes keep separate registry files. Mixing them up restores
# an installer's keys into a game, or drops a game's settings on backup.
###########################################################

@pytest.fixture
def registry_dir(tmp_path):
    profile = tmp_path / "profile"
    (profile / config.computer_folder_registry).mkdir(parents = True)
    return profile


def prefix(profile, prefix_name):
    entry = WINE(prefix_name = prefix_name)
    if profile:
        entry.set_prefix_user_profile_dir(str(profile))
    return entry


@pytest.fixture
def imported(monkeypatch):
    calls = []
    monkeypatch.setattr(registry, "import_registry_file", lambda **kwargs: calls.append(kwargs) or True)
    return calls


@pytest.fixture
def backed_up(monkeypatch):
    calls = []
    monkeypatch.setattr(registry, "backup_user_registry", lambda **kwargs: calls.append(kwargs) or True)
    return calls


###########################################################
# Restore
###########################################################

def test_restoring_without_a_profile_fails(imported):
    assert sandbox.restore_registry(prefix(None, config.PrefixType.GAME)) is False
    assert imported == []


@pytest.mark.parametrize("prefix_name, filename", [
    (config.PrefixType.SETUP, config.registry_filename_setup),
    (config.PrefixType.GAME, config.registry_filename_game),
])
def test_each_prefix_restores_its_own_registry_file(registry_dir, imported, prefix_name, filename):
    registry_file = registry_dir / config.computer_folder_registry / filename
    registry_file.write_text("REGEDIT4")

    assert sandbox.restore_registry(prefix(registry_dir, prefix_name), verbose = True, pretend_run = True) is True
    assert imported[0]["registry_file"] == str(registry_file)
    assert imported[0]["verbose"] is True
    assert imported[0]["pretend_run"] is True


def test_a_missing_registry_file_is_nothing_to_restore(registry_dir, imported):
    assert sandbox.restore_registry(prefix(registry_dir, config.PrefixType.GAME)) is True
    assert imported == []


def test_a_prefix_without_its_own_registry_restores_nothing(registry_dir, imported):
    assert sandbox.restore_registry(prefix(registry_dir, config.PrefixType.TOOL)) is True
    assert imported == []


def test_a_failed_import_is_reported(registry_dir, monkeypatch):
    (registry_dir / config.computer_folder_registry / config.registry_filename_game).write_text("")
    monkeypatch.setattr(registry, "import_registry_file", lambda **kwargs: False)

    assert sandbox.restore_registry(prefix(registry_dir, config.PrefixType.GAME)) is False


###########################################################
# Backup
###########################################################

@pytest.mark.parametrize("keys", [[], None])
def test_no_keys_to_keep_is_nothing_to_back_up(backed_up, keys):
    assert sandbox.backup_registry(prefix(None, config.PrefixType.GAME), registry_keys = keys) is True
    assert backed_up == []


def test_backing_up_without_a_profile_fails(backed_up):
    assert sandbox.backup_registry(prefix(None, config.PrefixType.GAME), registry_keys = ["HKCU"]) is False
    assert backed_up == []


def test_a_setup_prefix_backs_up_with_the_setup_rules(registry_dir, backed_up):
    assert sandbox.backup_registry(
        prefix(registry_dir, config.PrefixType.SETUP), registry_keys = ["HKCU\\Software\\Game"]) is True

    call = backed_up[0]
    assert call["registry_file"] == os.path.join(
        str(registry_dir), config.computer_folder_registry, config.registry_filename_setup)
    assert call["export_keys"] == config.registry_export_keys_setup
    assert call["ignore_keys"] == config.ignored_registry_keys_setup
    assert call["keep_keys"] == ["HKCU\\Software\\Game"]


def test_a_game_prefix_backs_up_with_the_game_rules(registry_dir, backed_up):
    assert sandbox.backup_registry(
        prefix(registry_dir, config.PrefixType.GAME), registry_keys = ["HKCU"], exit_on_failure = True) is True

    call = backed_up[0]
    assert call["registry_file"].endswith(config.registry_filename_game)
    assert call["export_keys"] == config.registry_export_keys_game
    assert call["ignore_keys"] == config.ignored_registry_keys_game
    assert call["exit_on_failure"] is True


def test_a_prefix_without_its_own_registry_cannot_be_backed_up(registry_dir, backed_up):
    # There is no file to write the keys to.
    assert sandbox.backup_registry(prefix(registry_dir, config.PrefixType.TOOL), registry_keys = ["HKCU"]) is False
    assert backed_up == []
