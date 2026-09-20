# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import steam


###########################################################
# Steam paths
#
# The prefix and manifest paths are how a Steam game's wine prefix and
# install state are found, so a wrong layout silently finds nothing.
###########################################################

INSTALL_DIR = "/home/user/.steam/steam"
APPID = "220"


def test_a_prefix_sits_under_compatdata():
    assert steam.get_steam_prefix_dir(INSTALL_DIR, APPID) == \
        os.path.join(INSTALL_DIR, "steamapps", "compatdata", APPID, "pfx")


def test_a_prefix_is_specific_to_the_app():
    assert steam.get_steam_prefix_dir(INSTALL_DIR, "220") != \
        steam.get_steam_prefix_dir(INSTALL_DIR, "440")


def test_a_prefix_sits_under_the_install_directory():
    assert steam.get_steam_prefix_dir(INSTALL_DIR, APPID).startswith(INSTALL_DIR)


def test_a_manifest_is_named_for_the_app():
    assert steam.get_steam_manifest_file(INSTALL_DIR, APPID) == \
        os.path.join(INSTALL_DIR, "steamapps", f"appmanifest_{APPID}.acf")


def test_a_manifest_is_specific_to_the_app():
    assert steam.get_steam_manifest_file(INSTALL_DIR, "220") != \
        steam.get_steam_manifest_file(INSTALL_DIR, "440")


def test_the_manifest_and_prefix_share_the_steamapps_root():
    prefix = steam.get_steam_prefix_dir(INSTALL_DIR, APPID)
    manifest = steam.get_steam_manifest_file(INSTALL_DIR, APPID)

    assert os.path.join(INSTALL_DIR, "steamapps") in prefix
    assert os.path.join(INSTALL_DIR, "steamapps") in manifest


@pytest.mark.parametrize("appid", ["220", "1091500", "0"])
def test_any_appid_builds_a_path(appid):
    assert appid in steam.get_steam_prefix_dir(INSTALL_DIR, appid)
    assert appid in steam.get_steam_manifest_file(INSTALL_DIR, appid)


def test_an_integer_appid_is_accepted():
    # App ids arrive from json as ints as often as strings.
    assert "220" in steam.get_steam_manifest_file(INSTALL_DIR, 220)


###########################################################
# Steam ids
###########################################################

@pytest.mark.parametrize("id_format", config.SteamIDFormatType.members())
def test_every_id_format_is_named(id_format):
    assert id_format.val()


def test_the_id_formats_are_distinct():
    values = [entry.val() for entry in config.SteamIDFormatType.members()]

    assert len(values) == len(set(values))


###########################################################
# Steam store pages and assets
#
# Each lookup probes a handful of CDN hosts and takes the first that answers.
# A probe that is skipped, or one whose result is not checked, leaves a game
# without its artwork rather than failing loudly.
###########################################################

@pytest.fixture
def reachable(monkeypatch):
    # Declares which urls answer, so the probing order is observable.
    state = {"ok": set(), "all": False, "probed": []}

    def is_url_reachable(url):
        state["probed"].append(url)
        if state["all"]:
            return True
        return url in state["ok"]

    monkeypatch.setattr(steam.network, "is_url_reachable", is_url_reachable)
    return state


def test_a_store_page_is_the_app_page(reachable):
    reachable["all"] = True

    assert steam.get_steam_page(APPID) == "https://store.steampowered.com/app/%s" % APPID


def test_a_store_page_that_does_not_answer_is_nothing(reachable):
    assert steam.get_steam_page(APPID) is None


def test_a_cover_is_taken_from_a_cdn_that_answers(reachable):
    reachable["all"] = True

    cover = steam.get_steam_cover(APPID)

    assert cover.endswith("/steam/apps/%s/library_600x900_2x.jpg" % APPID)


def test_every_cdn_is_tried_for_a_cover(reachable):
    # One CDN being down should not cost the cover.
    assert steam.get_steam_cover(APPID) is None
    assert len(reachable["probed"]) == len(config.ContentDeliveryNetworkType.members())


def test_a_cover_stops_at_the_first_cdn_that_answers(reachable):
    first = config.ContentDeliveryNetworkType.members()[0]
    reachable["ok"].add(
        "https://cdn.%s.steamstatic.com/steam/apps/%s/library_600x900_2x.jpg"
        % (first.lower(), APPID))

    steam.get_steam_cover(APPID)

    assert len(reachable["probed"]) == 1


def test_a_trailer_is_scraped_from_the_store_page(reachable, monkeypatch):
    reachable["all"] = True
    monkeypatch.setattr(
        steam.webpage, "get_matching_url",
        lambda **kwargs: "https://video.cdn.steamstatic.com/store_trailers/movie.mp4")

    assert steam.get_steam_trailer(APPID).endswith(".mp4")


def test_a_trailer_is_looked_for_as_a_video_file(reachable, monkeypatch):
    reachable["all"] = True
    seen = {}

    def get_matching_url(**kwargs):
        seen.update(kwargs)
        return None

    monkeypatch.setattr(steam.webpage, "get_matching_url", get_matching_url)
    steam.get_steam_trailer(APPID)

    assert seen["ends_with"] == ".mp4"
    assert seen["starts_with"].startswith("https://video.")


def test_no_trailer_anywhere_is_nothing(reachable, monkeypatch):
    reachable["all"] = True
    monkeypatch.setattr(steam.webpage, "get_matching_url", lambda **kwargs: None)

    assert steam.get_steam_trailer(APPID) is None


###########################################################
# Matching a game to an appid
###########################################################

@pytest.fixture
def appid_list(monkeypatch):
    # Stands in for the downloaded appid csv.
    state = {"rows": []}
    monkeypatch.setattr(
        steam.programs, "get_tool_path_config_value", lambda tool, key: "/tools/appids.csv")
    monkeypatch.setattr(
        steam.serialization, "read_csv_file", lambda **kwargs: state["rows"])
    return state


def row(appid, title):
    return {config.search_result_key_id: appid, config.search_result_key_title: title}


def test_a_matching_title_is_found(appid_list):
    appid_list["rows"] = [row("220", "Half-Life 2")]

    results = steam.find_steam_appid_matches("Half-Life 2")

    assert [result.get_id() for result in results] == ["220"]


def test_an_unrelated_title_is_not_matched(appid_list):
    appid_list["rows"] = [row("220", "Half-Life 2"), row("400", "Portal")]

    results = steam.find_steam_appid_matches("Half-Life 2")

    assert [result.get_title() for result in results] == ["Half-Life 2"]


def test_a_match_carries_how_close_it_was(appid_list):
    appid_list["rows"] = [row("220", "Half-Life 2")]

    assert steam.find_steam_appid_matches("Half-Life 2")[0].get_relevance() > 0


def test_an_empty_list_matches_nothing(appid_list):
    assert steam.find_steam_appid_matches("Half-Life 2") == []


def test_the_closest_match_with_a_live_page_is_taken(appid_list, reachable):
    # The csv carries every appid Steam ever had, including delisted ones.
    reachable["all"] = True
    appid_list["rows"] = [row("220", "Half-Life 2"), row("219", "Half-Life 2 Demo")]

    assert steam.find_steam_appid_match("Half-Life 2").get_id() == "220"


def test_a_delisted_match_is_passed_over(appid_list, reachable):
    # The csv keeps delisted appids, and the closest title is often the one
    # whose page is gone.
    appid_list["rows"] = [row("220", "Half-Life 2"), row("219", "Half Life 2")]
    reachable["ok"].add("https://store.steampowered.com/app/219")

    assert steam.find_steam_appid_match("Half-Life 2").get_id() == "219"


def test_no_live_page_anywhere_matches_nothing(appid_list, reachable):
    appid_list["rows"] = [row("220", "Half-Life 2")]

    assert steam.find_steam_appid_match("Half-Life 2") is None


def test_the_page_check_can_be_skipped(appid_list, reachable):
    appid_list["rows"] = [row("220", "Half-Life 2")]

    assert steam.find_steam_appid_match(
        "Half-Life 2", only_active_pages = False).get_id() == "220"
    assert reachable["probed"] == []


def test_nothing_to_match_yields_nothing(appid_list, reachable):
    assert steam.find_steam_appid_match("Half-Life 2") is None


###########################################################
# Finding assets for a game
###########################################################

def test_a_cover_is_found_for_a_matched_game(appid_list, reachable):
    reachable["all"] = True
    appid_list["rows"] = [row("220", "Half-Life 2")]

    results = steam.find_steam_assets("Half-Life 2", config.AssetType.BOXFRONT)

    assert len(results) == 1
    assert results[0].get_url().endswith("library_600x900_2x.jpg")


def test_a_video_is_found_for_a_matched_game(appid_list, reachable, monkeypatch):
    reachable["all"] = True
    appid_list["rows"] = [row("220", "Half-Life 2")]
    monkeypatch.setattr(
        steam.webpage, "get_matching_url",
        lambda **kwargs: "https://video.cdn.steamstatic.com/store_trailers/movie.mp4")

    results = steam.find_steam_assets("Half-Life 2", config.AssetType.VIDEO)

    assert results[0].get_url().endswith(".mp4")


def test_a_game_that_cannot_be_matched_has_no_assets(appid_list, reachable):
    assert steam.find_steam_assets("Half-Life 2", config.AssetType.BOXFRONT) == []


@pytest.mark.parametrize("asset_type", [
    config.AssetType.BACKGROUND,
    config.AssetType.BOXBACK,
    config.AssetType.SCREENSHOT,
])
def test_an_asset_type_steam_does_not_serve_yields_nothing(appid_list, reachable, asset_type):
    # Only the cover and the trailer have a known url shape; anything else
    # has to come from another source rather than a guessed url.
    reachable["all"] = True
    appid_list["rows"] = [row("220", "Half-Life 2")]

    assert steam.find_steam_assets("Half-Life 2", asset_type) == []


###########################################################
# Steam user ids
#
# The same account is addressed four different ways depending on which file
# is being read, and a wrong conversion points at another user's data.
###########################################################

STEAMID64 = "76561197960287930"
ACCOUNT = int(STEAMID64) - 76561197960265728


@pytest.fixture
def steam_store(isolated_settings, tmp_path):
    install_dir = tmp_path / "steam"
    install_dir.mkdir()
    for key, value in [
        ("steam_platform", "linux"),
        ("steam_arch", "64"),
        ("steam_accountname", "player"),
        ("steam_username", "Player"),
        ("steam_userid", STEAMID64),
        ("steam_web_api_key", "apikey"),
        ("steam_install_dir", str(install_dir)),
    ]:
        isolated_settings.set_value("UserData.Steam", key, value)
    return steam.Steam()


def test_the_default_id_is_the_64_bit_one(steam_store):
    assert steam_store.get_user_id() == STEAMID64


def test_the_long_account_id_is_bracketed(steam_store):
    assert steam_store.get_user_id(config.SteamIDFormatType.STEAMID_3L) == \
        "[U:1:%d]" % ACCOUNT


def test_the_short_account_id_is_the_bare_number(steam_store):
    assert steam_store.get_user_id(config.SteamIDFormatType.STEAMID_3S) == str(ACCOUNT)


def test_the_classic_id_carries_its_parity(steam_store):
    # STEAM_0:Y:Z splits the account id into a parity bit and a half, and
    # getting the parity wrong names a different account.
    classic = steam_store.get_user_id(config.SteamIDFormatType.STEAMID_CL)

    assert classic.startswith("STEAM_0:")
    assert classic == "STEAM_0:%d:%d" % (ACCOUNT % 2, ACCOUNT // 2)


def test_the_short_classic_id_is_the_halved_account(steam_store):
    assert steam_store.get_user_id(config.SteamIDFormatType.STEAMID_CS) == str(ACCOUNT // 2)


def test_every_id_format_produces_something_different(steam_store):
    produced = [
        steam_store.get_user_id(format_type)
        for format_type in config.SteamIDFormatType.members()
    ]

    assert len(set(produced)) == len(produced)


###########################################################
# Store identity
###########################################################

def test_the_store_knows_its_own_name(steam_store):
    assert steam_store.get_name() == config.StoreType.STEAM.val()


def test_the_store_reports_its_configured_account(steam_store):
    assert steam_store.get_account_name() == "player"
    assert steam_store.get_user_name() == "Player"


def test_the_store_reports_its_install_directory(steam_store, tmp_path):
    assert steam_store.get_install_dir() == str(tmp_path / "steam")


def test_the_store_can_install_and_launch(steam_store):
    # Steam is one of the few stores that owns the whole lifecycle.
    assert steam_store.can_handle_installing() is True
    assert steam_store.can_handle_launching() is True


def test_the_store_can_import_and_download_purchases(steam_store):
    assert steam_store.can_import_purchases() is True
    assert steam_store.can_download_purchases() is True


@pytest.mark.parametrize("key,value", [
    ("steam_platform", ""),
    ("steam_accountname", ""),
    ("steam_username", ""),
    ("steam_web_api_key", ""),
])
def test_a_store_without_its_settings_refuses_to_start(isolated_settings, tmp_path, key, value):
    # Half-configured, the store would build paths against empty values.
    install_dir = tmp_path / "steam"
    install_dir.mkdir()
    for setting_key, setting_value in [
        ("steam_platform", "linux"),
        ("steam_arch", "64"),
        ("steam_accountname", "player"),
        ("steam_username", "Player"),
        ("steam_userid", STEAMID64),
        ("steam_web_api_key", "apikey"),
        ("steam_install_dir", str(install_dir)),
    ]:
        isolated_settings.set_value("UserData.Steam", setting_key, setting_value)
    isolated_settings.set_value("UserData.Steam", key, value)

    with pytest.raises(RuntimeError):
        steam.Steam()
