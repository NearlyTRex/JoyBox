# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import gog
from gog_helpers import GOG_SETTINGS


###########################################################
# Construction
###########################################################

@pytest.mark.parametrize("missing", [key for key, _ in GOG_SETTINGS] + ["gog_install_dir"])
def test_every_setting_is_required(isolated_settings, tmp_path, missing):
    for key, value in GOG_SETTINGS + [("gog_install_dir", str(tmp_path))]:
        isolated_settings.set_value("UserData.GOG", key, "" if key == missing else value)

    with pytest.raises(RuntimeError):
        gog.GOG()


def test_the_store_describes_itself(gog_store):
    assert gog_store.get_name() == config.StoreType.GOG.val()
    assert gog_store.get_type() == config.StoreType.GOG
    assert gog_store.get_platform() == config.Platform.COMPUTER_GOG
    assert gog_store.get_supercategory() == config.Supercategory.ROMS
    assert gog_store.get_category() == config.Category.COMPUTER
    assert gog_store.get_subcategory() == config.Subcategory.COMPUTER_GOG
    assert gog_store.get_key() == config.json_key_gog
    assert gog_store.get_preferred_platform() == "windows"
    assert gog_store.get_user_name() == "player"
    assert gog_store.get_email() == "player@joybox.test"
    assert os.path.isdir(gog_store.get_install_dir())
    assert gog_store.can_handle_installing()
    assert gog_store.can_import_purchases() and gog_store.can_download_purchases()


def test_launching_is_not_offered(gog_store):
    assert gog_store.can_handle_launching() is False
    assert gog_store.launch("1207658924") is False


def test_identifiers_split_between_id_name_and_page(gog_store):
    keys = gog_store.get_identifier_keys()

    assert keys[config.StoreIdentifierType.INFO] == config.json_key_store_appid
    assert keys[config.StoreIdentifierType.INSTALL] == config.json_key_store_appid
    assert keys[config.StoreIdentifierType.LAUNCH] == config.json_key_store_appname
    assert keys[config.StoreIdentifierType.DOWNLOAD] == config.json_key_store_appname
    assert keys[config.StoreIdentifierType.PAGE] == config.json_key_store_appname
    assert keys[config.StoreIdentifierType.ASSET] == config.json_key_store_appurl
    assert keys[config.StoreIdentifierType.METADATA] == config.json_key_store_appurl


def test_the_latest_url_is_the_store_page(gog_store):
    assert gog_store.get_latest_url("the_witcher") == "https://www.gog.com/en/game/the_witcher"
    assert gog_store.get_latest_url("") is None


###########################################################
# Logging in
###########################################################

def test_login_signs_in_both_tools_once(gog_store, tools, recording_command):
    assert gog_store.login() is True
    assert gog_store.login() is True

    assert [call["cmd"] for call in recording_command.calls] == [
        ["/tools/lgogdownloader", "--login"],
        ["/tools/python", "/tools/gogdl/login.py", "/tools/gogdl/auth.json"]]
    assert recording_command.options(0).get_blocking_processes() == ["/tools/lgogdownloader"]
    assert gog_store.is_logged_in() is True


def test_a_failed_lgogdownloader_login_stops_there(gog_store, tools, recording_command):
    recording_command.returncode = 1

    assert gog_store.login() is False
    assert len(recording_command.calls) == 1
    assert gog_store.is_logged_in() is False


def test_a_failed_gogdl_login_is_not_remembered(gog_store, tools, monkeypatch):
    codes = iter([0, 1])
    monkeypatch.setattr(gog.command, "run_interactive_command", lambda cmd, **kwargs: next(codes))

    assert gog_store.login() is False
    assert gog_store.is_logged_in() is False


def test_login_needs_lgogdownloader(gog_store, tools, recording_command):
    del tools["programs"]["LGOGDownloader"]

    assert gog_store.login() is False
    assert recording_command.calls == []


@pytest.mark.parametrize("missing", ["PythonVenvPython", "HeroicGogDL"])
def test_gogdl_login_needs_python_and_gogdl(gog_store, tools, recording_command, missing):
    del tools["programs"][missing]

    assert gog_store.login_heroic_gogdl() is False
    assert recording_command.calls == []


@pytest.mark.parametrize("key", ["login_script", "auth_json"])
def test_gogdl_login_needs_its_script_and_auth_file(gog_store, tools, recording_command, key):
    del tools["paths"][("HeroicGogDL", key)]

    assert gog_store.login_heroic_gogdl() is False
    assert recording_command.calls == []


###########################################################
# Installing
###########################################################

def test_install_downloads_into_a_folder_per_game(gog_store, tools, recording_command):
    assert gog_store.install("1207658924") is True

    assert recording_command.only() == [
        "/tools/python", "/tools/gogdl/main.py",
        "--auth-config-path", "/tools/gogdl/auth.json",
        "download", "1207658924",
        "--platform", "windows",
        "--path", os.path.join(gog_store.get_install_dir(), "1207658924")]


@pytest.mark.parametrize("platform,gogdl_platform", [("windows", "windows"), ("linux", "linux"), ("mac", "osx")])
def test_install_uses_the_preferred_platform(gog_store, tools, recording_command, platform, gogdl_platform):
    gog_store.platform = platform

    gog_store.install("1207658924")

    assert recording_command.value_after("--platform") == gogdl_platform


def test_install_passes_pretend_run_through(gog_store, tools, recording_command):
    gog_store.install("1207658924", pretend_run = True)

    assert recording_command.calls[0]["kwargs"]["pretend_run"] is True


def test_a_failed_install_is_reported(gog_store, tools, recording_command):
    recording_command.returncode = 1

    assert gog_store.install("1207658924") is False


def test_an_invalid_install_identifier_runs_nothing(gog_store, tools, recording_command):
    assert gog_store.install("") is False
    assert recording_command.calls == []


@pytest.mark.parametrize("missing", ["PythonVenvPython", "HeroicGogDL"])
def test_install_needs_python_and_gogdl(gog_store, tools, recording_command, missing):
    del tools["programs"][missing]

    assert gog_store.install("1207658924") is False
    assert recording_command.calls == []


def test_install_needs_the_auth_file(gog_store, tools, recording_command):
    del tools["paths"][("HeroicGogDL", "auth_json")]

    assert gog_store.install("1207658924") is False
    assert recording_command.calls == []


def test_a_game_is_installed_when_its_folder_has_files(gog_store):
    game_dir = os.path.join(gog_store.get_install_dir(), "1207658924")

    assert gog_store.is_installed("1207658924") is False
    os.makedirs(game_dir)
    assert gog_store.is_installed("1207658924") is False
    open(os.path.join(game_dir, "game.exe"), "w").close()

    assert gog_store.is_installed("1207658924") is True
    assert gog_store.is_installed("") is False
