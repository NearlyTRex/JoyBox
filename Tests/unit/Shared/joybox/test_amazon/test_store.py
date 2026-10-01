# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import amazon
from amazon_helpers import NILE, PYTHON


###########################################################
# Construction
###########################################################

def test_an_install_dir_is_required(isolated_settings):
    isolated_settings.set_value("UserData.Amazon", "amazon_install_dir", "")

    with pytest.raises(RuntimeError):
        amazon.Amazon()


def test_the_install_dir_expands_variables(isolated_settings, tmp_path, monkeypatch):
    monkeypatch.setenv("AMAZON_TEST_ROOT", str(tmp_path))
    isolated_settings.set_value("UserData.Amazon", "amazon_install_dir", "$AMAZON_TEST_ROOT/games")

    assert amazon.Amazon().get_install_dir() == os.path.join(str(tmp_path), "games")


def test_the_store_describes_itself(amazon_store):
    assert amazon_store.get_name() == config.StoreType.AMAZON.val()
    assert amazon_store.get_type() == config.StoreType.AMAZON
    assert amazon_store.get_platform() == config.Platform.COMPUTER_AMAZON_GAMES
    assert amazon_store.get_supercategory() == config.Supercategory.ROMS
    assert amazon_store.get_category() == config.Category.COMPUTER
    assert amazon_store.get_subcategory() == config.Subcategory.COMPUTER_AMAZON_GAMES
    assert amazon_store.get_key() == config.json_key_amazon
    assert amazon_store.can_import_purchases() and amazon_store.can_download_purchases()


def test_the_install_dir_comes_from_settings(amazon_store, tmp_path):
    assert amazon_store.get_install_dir() == str(tmp_path / "amazon")


def test_names_find_pages_and_appids_find_everything_else(amazon_store):
    keys = amazon_store.get_identifier_keys()

    by_name = [config.StoreIdentifierType.ASSET, config.StoreIdentifierType.METADATA, config.StoreIdentifierType.PAGE]
    by_appid = [config.StoreIdentifierType.INFO, config.StoreIdentifierType.INSTALL,
                config.StoreIdentifierType.LAUNCH, config.StoreIdentifierType.DOWNLOAD]
    assert all(keys[kind] == config.json_key_store_name for kind in by_name)
    assert all(keys[kind] == config.json_key_store_appid for kind in by_appid)
    assert len(keys) == len(by_name) + len(by_appid)


###########################################################
# Logging in
###########################################################

def test_login_authenticates_then_refreshes_once(amazon_store, tools, recording_command):
    assert amazon_store.login() is True
    assert amazon_store.login() is True

    assert [call["cmd"] for call in recording_command.calls] == [
        [PYTHON, NILE, "--quiet", "auth", "--login"],
        [PYTHON, NILE, "--quiet", "auth", "--refresh"]]
    assert amazon_store.is_logged_in() is True


def test_login_passes_its_flags_through(amazon_store, tools, recording_command):
    amazon_store.login(verbose = True, pretend_run = True, exit_on_failure = True)

    for call in recording_command.calls:
        assert call["kwargs"] == {"verbose": True, "pretend_run": True, "exit_on_failure": True}


def test_a_failed_login_skips_the_refresh(amazon_store, tools, recording_command):
    recording_command.returncode = 1

    assert amazon_store.login() is False
    assert len(recording_command.calls) == 1
    assert amazon_store.is_logged_in() is False


def test_a_failed_refresh_is_not_remembered(amazon_store, tools, monkeypatch):
    codes = [0, 1]
    monkeypatch.setattr(amazon.command, "run_interactive_command", lambda **kwargs: codes.pop(0))

    assert amazon_store.login() is False
    assert amazon_store.is_logged_in() is False


@pytest.mark.parametrize("tool", ["PythonVenvPython", "Nile"])
def test_login_needs_python_and_nile(amazon_store, tools, recording_command, tool):
    del tools[tool]

    assert amazon_store.login() is False
    assert recording_command.calls == []
