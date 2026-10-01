# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import legacy
from legacy_helpers import HEIRLOOM


###########################################################
# Construction
###########################################################

def test_a_username_is_required(isolated_settings, tmp_path):
    isolated_settings.set_value("UserData.Legacy", "legacy_username", "")
    isolated_settings.set_value("UserData.Legacy", "legacy_install_dir", str(tmp_path))

    with pytest.raises(RuntimeError):
        legacy.Legacy()


def test_an_install_dir_is_required(isolated_settings):
    isolated_settings.set_value("UserData.Legacy", "legacy_username", "player")
    isolated_settings.set_value("UserData.Legacy", "legacy_install_dir", "")

    with pytest.raises(RuntimeError):
        legacy.Legacy()


def test_the_store_describes_itself(legacy_store, tmp_path):
    assert legacy_store.get_name() == config.StoreType.LEGACY.val()
    assert legacy_store.get_type() == config.StoreType.LEGACY
    assert legacy_store.get_platform() == config.Platform.COMPUTER_LEGACY_GAMES
    assert legacy_store.get_supercategory() == config.Supercategory.ROMS
    assert legacy_store.get_category() == config.Category.COMPUTER
    assert legacy_store.get_subcategory() == config.Subcategory.COMPUTER_LEGACY_GAMES
    assert legacy_store.get_key() == config.json_key_legacy
    assert legacy_store.get_user_name() == "player"
    assert legacy_store.get_install_dir() == str(tmp_path / "legacy")
    assert legacy_store.can_import_purchases() and legacy_store.can_download_purchases()


def test_assets_use_the_page_metadata_the_name_and_everything_else_the_appid(legacy_store):
    keys = legacy_store.get_identifier_keys()

    assert keys.pop(config.StoreIdentifierType.ASSET) == config.json_key_store_appurl
    assert keys.pop(config.StoreIdentifierType.METADATA) == config.json_key_store_name
    assert set(keys.values()) == {config.json_key_store_appid}


###########################################################
# Logging in
###########################################################

def test_login_runs_heirloom_login_then_refresh_once(legacy_store, tools, recording_command):
    assert legacy_store.login() is True
    assert legacy_store.login() is True

    assert [call["cmd"] for call in recording_command.calls] == [HEIRLOOM + ["login"], HEIRLOOM + ["refresh"]]
    assert legacy_store.is_logged_in() is True


def test_login_passes_its_run_flags_through(legacy_store, tools, recording_command):
    legacy_store.login(verbose = True, pretend_run = True, exit_on_failure = True)

    for call in recording_command.calls:
        assert call["kwargs"] == {"verbose": True, "pretend_run": True, "exit_on_failure": True}


def test_a_failed_login_skips_the_refresh_and_is_not_remembered(legacy_store, tools, recording_command):
    recording_command.returncode = 1

    assert legacy_store.login() is False
    assert recording_command.only() == HEIRLOOM + ["login"]
    assert legacy_store.is_logged_in() is False


def test_a_failed_refresh_is_not_remembered(legacy_store, tools, monkeypatch):
    ran = []

    def run_interactive_command(cmd, **kwargs):
        ran.append(cmd[-1])
        return 0 if cmd[-1] == "login" else 1

    monkeypatch.setattr(legacy.command, "run_interactive_command", run_interactive_command)

    assert legacy_store.login() is False
    assert ran == ["login", "refresh"]
    assert legacy_store.is_logged_in() is False


@pytest.mark.parametrize("tool", ["PythonVenvPython", "Heirloom"])
def test_login_needs_python_and_heirloom(legacy_store, tools, recording_command, tool):
    del tools[tool]

    assert legacy_store.login() is False
    assert recording_command.calls == []
