# Imports
import json
import os
import time

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import epic
from epic_helpers import LEGENDARY, legendary_list, listed_game


###########################################################
# Construction
###########################################################

def test_a_username_is_required(isolated_settings, tmp_path):
    isolated_settings.set_value("UserData.Epic", "epic_username", "")
    isolated_settings.set_value("UserData.Epic", "epic_install_dir", str(tmp_path))

    with pytest.raises(RuntimeError):
        epic.Epic()


def test_an_install_dir_is_required(isolated_settings):
    isolated_settings.set_value("UserData.Epic", "epic_username", "player")
    isolated_settings.set_value("UserData.Epic", "epic_install_dir", "")

    with pytest.raises(RuntimeError):
        epic.Epic()


def test_the_store_describes_itself(epic_store, tmp_path):
    assert epic_store.get_name() == config.StoreType.EPIC.val()
    assert epic_store.get_type() == config.StoreType.EPIC
    assert epic_store.get_platform() == config.Platform.COMPUTER_EPIC_GAMES
    assert epic_store.get_supercategory() == config.Supercategory.ROMS
    assert epic_store.get_category() == config.Category.COMPUTER
    assert epic_store.get_subcategory() == config.Subcategory.COMPUTER_EPIC_GAMES
    assert epic_store.get_key() == config.json_key_epic
    assert epic_store.get_user_name() == "player"
    assert epic_store.get_install_dir() == str(tmp_path / "epic")
    assert epic_store.can_handle_installing() and epic_store.can_handle_launching()
    assert epic_store.can_import_purchases() and epic_store.can_download_purchases()


def test_metadata_is_found_by_page_and_everything_else_by_appname(epic_store):
    keys = epic_store.get_identifier_keys()

    assert keys.pop(config.StoreIdentifierType.METADATA) == config.json_key_store_appurl
    assert set(keys.values()) == {config.json_key_store_appname}


###########################################################
# Logging in
###########################################################

def test_login_runs_legendary_auth_once(epic_store, tools, recording_command):
    assert epic_store.login() is True
    assert epic_store.login() is True

    assert recording_command.only() == LEGENDARY + ["auth"]


def test_a_failed_login_is_not_remembered(epic_store, tools, recording_command):
    recording_command.returncode = 1

    assert epic_store.login() is False
    assert epic_store.is_logged_in() is False


@pytest.mark.parametrize("tool", ["PythonVenvPython", "Legendary"])
def test_login_needs_python_and_legendary(epic_store, tools, recording_command, tool):
    del tools[tool]

    assert epic_store.login() is False
    assert recording_command.calls == []


###########################################################
# Purchases
###########################################################

@pytest.fixture
def owned(epic_store, tools, recording_command, monkeypatch, tmp_path):
    monkeypatch.setattr(epic_store, "get_purchases_cache_dir", lambda: str(tmp_path / "cache"))
    recording_command.output = legendary_list(
        listed_game("Fortnite", "Fortnite", build = "++Fortnite+Release-30.00"),
        listed_game("Sugar", "Hades"))
    return tmp_path / "cache" / "epic_purchases_cache.json"


def test_owned_games_become_purchases(epic_store, owned, recording_command):
    purchases = epic_store.get_latest_purchases()

    assert recording_command.only() == LEGENDARY + ["list", "--json"]
    assert [p.get_value(config.json_key_store_appname) for p in purchases] == ["Fortnite", "Sugar"]
    assert [p.get_value(config.json_key_store_name) for p in purchases] == ["Fortnite", "Hades"]
    assert purchases[0].get_value(config.json_key_store_buildid) == "++Fortnite+Release-30.00"
    assert purchases[0].get_value(config.json_key_store_appurl) == ""


def test_a_game_without_a_windows_build_gets_the_default_build(epic_store, owned):
    purchases = epic_store.get_latest_purchases()

    assert purchases[1].get_value(config.json_key_store_buildid) == config.default_buildid


def test_null_listing_fields_are_tolerated(epic_store, owned, recording_command):
    recording_command.output = json.dumps([{"app_name": "Sugar", "app_title": None, "asset_infos": None}])

    purchase = epic_store.get_latest_purchases()[0]

    assert purchase.get_value(config.json_key_store_name) == ""
    assert purchase.get_value(config.json_key_store_buildid) == config.default_buildid


def test_purchases_are_cached_for_a_day(epic_store, owned, recording_command):
    epic_store.get_latest_purchases(verbose = True)
    recording_command.output = legendary_list()

    again = epic_store.get_latest_purchases(verbose = True)

    assert len(recording_command.calls) == 1
    assert [p.get_value(config.json_key_store_appname) for p in again] == ["Fortnite", "Sugar"]
    assert again[0].get_value(config.json_key_store_buildid) == "++Fortnite+Release-30.00"


def test_an_empty_library_is_cached_too(epic_store, owned, recording_command):
    recording_command.output = legendary_list()

    assert epic_store.get_latest_purchases() == []
    assert epic_store.get_latest_purchases() == []
    assert len(recording_command.calls) == 1


def test_a_stale_cache_is_refreshed(epic_store, owned, recording_command):
    epic_store.get_latest_purchases()
    day_ago = time.time() - 25 * 3600
    os.utime(owned, (day_ago, day_ago))

    epic_store.get_latest_purchases()

    assert len(recording_command.calls) == 2


@pytest.mark.parametrize("cached", [{"not": "a list"}, ["not a dict"]])
@pytest.mark.parametrize("verbose", [False, True])
def test_an_unreadable_cache_is_refetched(epic_store, owned, recording_command, verbose, cached):
    owned.parent.mkdir(parents = True)
    owned.write_text(json.dumps(cached))

    assert len(epic_store.get_latest_purchases(verbose = verbose)) == 2
    assert len(recording_command.calls) == 1


@pytest.mark.parametrize("output", ["", "not json", json.dumps({"app_name": "Sugar"})])
def test_unusable_listings_give_no_purchases(epic_store, owned, recording_command, output):
    recording_command.output = output

    assert epic_store.get_latest_purchases() is None
    assert not owned.exists()


@pytest.mark.parametrize("tool", ["PythonVenvPython", "Legendary"])
def test_purchases_need_python_and_legendary(epic_store, owned, tools, recording_command, tool):
    del tools[tool]

    assert epic_store.get_latest_purchases() is None
    assert recording_command.calls == []


@pytest.mark.parametrize("verbose", [False, True])
def test_a_failed_cache_write_still_returns_purchases(epic_store, owned, monkeypatch, verbose):
    monkeypatch.setattr(epic.serialization, "write_json_file", lambda **kwargs: False)

    assert len(epic_store.get_latest_purchases(verbose = verbose)) == 2
