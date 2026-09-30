# Imports
import json
import os
import time

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import steam
from steam_helpers import STEAM_SETTINGS, STEAMID64


@pytest.fixture
def tools(monkeypatch):
    installed = {"SteamCMD": "/tools/steamcmd", "Steam": "/tools/steam", "SteamDepotDownloader": "/tools/depot"}
    monkeypatch.setattr(steam.programs, "is_tool_installed", lambda name: name in installed)
    monkeypatch.setattr(steam.programs, "get_tool_program", lambda name: installed.get(name))
    return installed


@pytest.fixture
def no_manifest(monkeypatch):
    class EmptyManifest:
        def find_entry_by_steamid(self, **kwargs):
            return None
        def find_entry_by_name(self, **kwargs):
            return None
    monkeypatch.setattr(steam.manifest, "get_manifest_instance", lambda: EmptyManifest())


###########################################################
# Construction
###########################################################

@pytest.mark.parametrize("missing", [key for key, _ in STEAM_SETTINGS if key != "steam_arch"] + ["steam_install_dir"])
def test_every_setting_is_required(isolated_settings, tmp_path, missing):
    for key, value in STEAM_SETTINGS + [("steam_install_dir", str(tmp_path))]:
        isolated_settings.set_value("UserData.Steam", key, "" if key == missing else value)

    with pytest.raises(RuntimeError):
        steam.Steam()


def test_the_store_describes_itself(steam_store):
    assert steam_store.get_name() == config.StoreType.STEAM.val()
    assert steam_store.get_type() == config.StoreType.STEAM
    assert steam_store.get_platform() == config.Platform.COMPUTER_STEAM
    assert steam_store.get_supercategory() == config.Supercategory.ROMS
    assert steam_store.get_category() == config.Category.COMPUTER
    assert steam_store.get_subcategory() == config.Subcategory.COMPUTER_STEAM
    assert steam_store.get_key() == config.json_key_steam
    assert steam_store.get_preferred_platform() == "linux"
    assert steam_store.get_preferred_architecture() == "64"
    assert steam_store.get_account_name() == "player"
    assert steam_store.get_user_name() == "Player"
    assert steam_store.get_web_api_key() == "apikey"
    assert steam_store.can_handle_installing() and steam_store.can_handle_launching()
    assert steam_store.can_import_purchases() and steam_store.can_download_purchases()


def test_metadata_is_found_by_page_and_everything_else_by_appid(steam_store):
    keys = steam_store.get_identifier_keys()

    assert keys.pop(config.StoreIdentifierType.METADATA) == config.json_key_store_appurl
    assert set(keys.values()) == {config.json_key_store_appid}


###########################################################
# Logging in
###########################################################

def test_login_runs_steamcmd_once(steam_store, tools, recording_command):
    assert steam_store.login() is True
    assert steam_store.login() is True

    assert recording_command.only() == ["/tools/steamcmd", "+login", "player", "+quit"]


def test_a_failed_login_is_not_remembered(steam_store, tools, recording_command):
    recording_command.returncode = 1

    assert steam_store.login() is False
    assert steam_store.is_logged_in() is False


def test_login_needs_steamcmd(steam_store, tools, recording_command):
    tools.clear()

    assert steam_store.login() is False
    assert recording_command.calls == []


###########################################################
# Purchases
###########################################################

@pytest.fixture
def owned(steam_store, reachable, monkeypatch, tmp_path):
    state = {"json": {"response": {"games": [{"appid": 220, "name": " Half-Life 2 "}, {"appid": 400, "name": "Portal"}]}},
             "fetched": []}
    reachable["all"] = True
    monkeypatch.setattr(steam_store, "get_purchases_cache_dir", lambda: str(tmp_path / "cache"))

    def get_remote_json(url, **kwargs):
        state["fetched"].append(url)
        return state["json"]
    monkeypatch.setattr(steam.network, "get_remote_json", get_remote_json)
    state["cache"] = tmp_path / "cache" / "steam_purchases_cache.json"
    return state


def test_owned_games_become_purchases(steam_store, owned, reachable):
    purchases = steam_store.get_latest_purchases()

    assert [p.get_value(config.json_key_store_appid) for p in purchases] == ["220", "400"]
    first = purchases[0]
    assert first.get_value(config.json_key_store_name) == "Half-Life 2"
    assert first.get_value(config.json_key_store_appurl) == "https://store.steampowered.com/app/220"
    assert first.get_value(config.json_key_store_branchid) == "public"
    assert "steamid=%s" % STEAMID64 in owned["fetched"][0]
    assert "key=apikey" in owned["fetched"][0]


def test_each_purchase_probes_its_page_once(steam_store, owned, reachable):
    steam_store.get_latest_purchases()

    pages = [url for url in reachable["probed"] if "/app/" in url]
    assert pages == ["https://store.steampowered.com/app/220", "https://store.steampowered.com/app/400"]


def test_purchases_are_cached_for_a_day(steam_store, owned):
    steam_store.get_latest_purchases(verbose = True)
    owned["json"] = {"response": {"games": []}}

    again = steam_store.get_latest_purchases(verbose = True)

    assert len(owned["fetched"]) == 1
    assert [p.get_value(config.json_key_store_appid) for p in again] == ["220", "400"]


def test_a_stale_cache_is_refreshed(steam_store, owned):
    steam_store.get_latest_purchases()
    day_ago = time.time() - 25 * 3600
    os.utime(owned["cache"], (day_ago, day_ago))

    steam_store.get_latest_purchases()

    assert len(owned["fetched"]) == 2


def test_an_unreadable_cache_is_refetched(steam_store, owned):
    owned["cache"].parent.mkdir(parents = True)
    owned["cache"].write_text(json.dumps({"not": "a list"}))

    assert len(steam_store.get_latest_purchases(verbose = True)) == 2
    assert len(owned["fetched"]) == 1


def test_purchases_need_the_api(steam_store, owned, reachable):
    owned["json"] = None
    assert steam_store.get_latest_purchases() is None

    reachable["all"] = False
    assert steam_store.get_latest_purchases() is None


def test_a_failed_cache_write_still_returns_purchases(steam_store, owned, monkeypatch):
    monkeypatch.setattr(steam.serialization, "write_json_file", lambda **kwargs: False)

    assert len(steam_store.get_latest_purchases(verbose = True)) == 2


###########################################################
# App info
###########################################################

APP_INFO = '''Connecting anonymously to Steam Public...OK
"220"
{
    "common"
    {
        "name"      " Half-Life 2 "
        "controller_support"        "full"
    }
    "config"
    {
        "installdir"        "Half-Life 2"
    }
    "depots"
    {
        "branches"
        {
            "public"
            {
                "buildid"       "100"
                "timeupdated"   "1700000000"
            }
            "beta"
            {
                "buildid"       "200"
            }
        }
    }
}
'''


def app_info(steam_store, recording_command, output, branch = None):
    recording_command.output = output
    return steam_store.get_latest_jsondata("220", branch = branch)


def test_app_info_is_parsed(steam_store, tools, recording_command, reachable, no_manifest):
    data = app_info(steam_store, recording_command, APP_INFO + "Unloading Steam API...\n")

    assert recording_command.only() == ["/tools/steamcmd", "+login", "anonymous", "+app_info_print", "220", "+quit"]
    assert data.get_value(config.json_key_store_name) == "Half-Life 2"
    assert data.get_value(config.json_key_store_controller_support) == "full"
    assert data.get_value(config.json_key_store_installdir) == "STORE_INSTALL_DIR/steamapps/common/Half-Life 2"
    assert data.get_value(config.json_key_store_builddate) == "1700000000"


def test_no_branch_reads_the_public_build(steam_store, tools, recording_command, reachable, no_manifest):
    data = app_info(steam_store, recording_command, APP_INFO)

    assert data.get_value(config.json_key_store_branchid) == "public"
    assert data.get_value(config.json_key_store_buildid) == "100"


def test_a_named_branch_reads_its_own_build(steam_store, tools, recording_command, reachable, no_manifest):
    data = app_info(steam_store, recording_command, APP_INFO, branch = "beta")

    assert data.get_value(config.json_key_store_branchid) == "beta"
    assert data.get_value(config.json_key_store_buildid) == "200"
    assert data.get_value(config.json_key_store_builddate) == "unknown"


def test_output_without_the_app_is_refused(steam_store, tools, recording_command, no_manifest):
    assert app_info(steam_store, recording_command, "Connecting...\nNo app info\n") is None
    assert app_info(steam_store, recording_command, '"220"\n{\n    "common" {\n') is None


def test_app_info_needs_output_steamcmd_and_an_id(steam_store, tools, recording_command):
    assert app_info(steam_store, recording_command, "") is None
    assert steam_store.get_latest_jsondata("") is None
    tools.clear()
    assert steam_store.get_latest_jsondata("220") is None


def test_manifest_paths_join_the_app_info(steam_store, tools, recording_command, reachable, monkeypatch):
    class Entry:
        def get_paths(self, base_path):
            return [base_path + "/saves", "GAME_INSTALL_DIR/cfg"]
        def get_keys(self):
            return ["HKEY_CURRENT_USER/Software/Valve"]

    class OneEntryManifest:
        def find_entry_by_steamid(self, steamid, **kwargs):
            return Entry() if steamid == "220" else None
        def find_entry_by_name(self, **kwargs):
            return None

    monkeypatch.setattr(steam.manifest, "get_manifest_instance", lambda: OneEntryManifest())
    data = app_info(steam_store, recording_command, APP_INFO)

    assert "GAME_INSTALL_DIR/cfg" in data.get_value(config.json_key_store_paths)
    assert data.get_value(config.json_key_store_keys) == ["HKEY_CURRENT_USER/Software/Valve"]


###########################################################
# Pages and assets
###########################################################

def test_the_latest_url_is_the_store_page(steam_store, reachable):
    reachable["all"] = True

    assert steam_store.get_latest_url("220") == "https://store.steampowered.com/app/220"
    assert steam_store.get_latest_url("") is None


def test_asset_urls_by_type(steam_store, reachable, monkeypatch):
    reachable["all"] = True
    monkeypatch.setattr(steam, "get_steam_trailer", lambda appid, **kwargs: "trailer-%s.mp4" % appid)

    assert "220/library_600x900_2x.jpg" in steam_store.get_latest_asset_url("220", config.AssetType.BOXFRONT)
    assert steam_store.get_latest_asset_url("220", config.AssetType.VIDEO) == "trailer-220.mp4"
    assert steam_store.get_latest_asset_url("220", config.AssetType.LABEL) is None
    assert steam_store.get_latest_asset_url("", config.AssetType.BOXFRONT) is None


###########################################################
# Installing and launching
###########################################################

def test_an_app_is_installed_when_its_manifest_exists(steam_store):
    assert steam_store.is_installed("220") is False
    steamapps = os.path.join(steam_store.get_install_dir(), "steamapps")
    os.makedirs(steamapps)
    open(os.path.join(steamapps, "appmanifest_220.acf"), "w").close()

    assert steam_store.is_installed("220") is True
    assert steam_store.is_installed("") is False


def test_install_passes_every_command_to_steamcmd(steam_store, tools, recording_command):
    # SteamCMD only runs arguments that start with a plus
    assert steam_store.install("220") is True

    assert recording_command.only() == [
        "/tools/steamcmd",
        "+@sSteamCmdForcePlatformType", "linux",
        "+login", "player",
        "+app_update", "220", "validate",
        "+quit"]


def test_launch_opens_the_steam_url(steam_store, tools, recording_command):
    assert steam_store.launch("220") is True

    assert recording_command.only() == ["/tools/steam", "steam://rungameid/220"]


@pytest.mark.parametrize("action", ["install", "launch"])
def test_a_failed_command_is_reported(steam_store, tools, recording_command, action):
    recording_command.returncode = 1

    assert getattr(steam_store, action)("220") is False


@pytest.mark.parametrize("action", ["install", "launch", "download"])
def test_an_invalid_identifier_runs_nothing(steam_store, tools, recording_command, tmp_path, action):
    args = ("", str(tmp_path)) if action == "download" else ("",)

    assert getattr(steam_store, action)(*args) is False
    assert recording_command.calls == []


@pytest.mark.parametrize("action,tool", [("install", "SteamCMD"), ("launch", "Steam"), ("download", "SteamDepotDownloader")])
def test_a_missing_tool_stops_the_program(steam_store, tools, recording_command, tmp_path, action, tool):
    del tools[tool]
    args = ("220", str(tmp_path)) if action == "download" else ("220",)

    with pytest.raises(SystemExit):
        getattr(steam_store, action)(*args)


###########################################################
# Downloading
###########################################################

@pytest.fixture
def depot(steam_store, tools, recording_command, monkeypatch, tmp_path):
    state = {"archived": [], "archive_ok": True, "temp": tmp_path / "depot-temp"}

    def create_temporary_directory(**kwargs):
        state["temp"].mkdir()
        return (True, str(state["temp"]))
    monkeypatch.setattr(steam.fileops, "create_temporary_directory", create_temporary_directory)

    def archive_folder(input_path, output_path, **kwargs):
        state["archived"].append((input_path, kwargs))
        if state["archive_ok"]:
            os.makedirs(output_path, exist_ok = True)
            open(os.path.join(output_path, "220.7z"), "w").close()
        return state["archive_ok"]
    monkeypatch.setattr(steam.backup, "archive_folder", archive_folder)
    return state


def test_a_download_is_archived_and_its_temp_removed(steam_store, depot, recording_command, tmp_path):
    output = tmp_path / "out"

    assert steam_store.download("220", str(output)) is True

    assert recording_command.only() == [
        "/tools/depot", "-app", "220", "-os", "linux", "-osarch", "64", "-dir", str(depot["temp"]),
        "-username", "player", "-remember-password"]
    assert depot["archived"][0][1]["excludes"] == [".DepotDownloader"]
    assert not depot["temp"].exists()


def test_a_beta_branch_is_downloaded_as_such(steam_store, depot, recording_command, tmp_path):
    steam_store.download("220", str(tmp_path / "out"), branch = "beta")
    steam_store.download("220", str(tmp_path / "out"), branch = "public")

    beta_cmd = recording_command.calls[0]["cmd"]
    assert beta_cmd[beta_cmd.index("-beta") + 1] == "beta"
    assert "-beta" not in recording_command.calls[1]["cmd"]


def test_a_failed_download_removes_its_temp(steam_store, depot, recording_command, tmp_path):
    recording_command.returncode = 1

    assert steam_store.download("220", str(tmp_path / "out")) is False
    assert depot["archived"] == []
    assert not depot["temp"].exists()


def test_a_failed_archive_removes_its_temp(steam_store, depot, tmp_path):
    depot["archive_ok"] = False

    assert steam_store.download("220", str(tmp_path / "out")) is False
    assert not depot["temp"].exists()


def test_a_download_needs_a_temp_directory(steam_store, depot, recording_command, monkeypatch, tmp_path):
    monkeypatch.setattr(steam.fileops, "create_temporary_directory", lambda **kwargs: (False, "no"))

    assert steam_store.download("220", str(tmp_path / "out")) is False
    assert recording_command.calls == []


###########################################################
# Paths
###########################################################

def test_the_prefix_joins_the_translation_map(steam_store):
    prefix = steam.get_steam_prefix_dir(steam_store.get_install_dir(), "220")

    translation_map = steam_store.build_path_translation_map(appid = "220")

    assert prefix in translation_map[config.token_user_registry_dir]
    assert os.path.join(prefix, "drive_c", "users", "steamuser") in translation_map[config.token_user_profile_dir]
    assert os.path.join(prefix, "drive_c", "users", "Public") in translation_map[config.token_user_public_dir]
    assert prefix not in str(steam_store.build_path_translation_map())


def test_user_id_paths_get_every_id_form(steam_store):
    variants = steam_store.add_path_variants(["userdata/STORE_USER_ID/220"])

    for format_type in [config.SteamIDFormatType.STEAMID_64, config.SteamIDFormatType.STEAMID_3S, config.SteamIDFormatType.STEAMID_CS]:
        assert "userdata/%s/220" % steam_store.get_user_id(format_type) in variants
