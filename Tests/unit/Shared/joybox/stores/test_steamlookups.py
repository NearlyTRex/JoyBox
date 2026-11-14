# Imports
import types

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import steamlookups
from stores_helpers import STEAM_APPID


###########################################################
# Steam store pages and assets
#
# Each lookup probes a handful of CDN hosts and takes the first that answers.
# A probe that is skipped, or one whose result is not checked, leaves a game
# without its artwork rather than failing loudly.
###########################################################

def test_a_store_page_is_the_app_page(reachable):
    reachable["all"] = True

    assert steamlookups.get_steam_page(STEAM_APPID) == "https://store.steampowered.com/app/%s" % STEAM_APPID


def test_a_store_page_that_does_not_answer_is_nothing(reachable):
    assert steamlookups.get_steam_page(STEAM_APPID) is None


def test_a_cover_is_taken_from_a_cdn_that_answers(reachable):
    reachable["all"] = True

    cover = steamlookups.get_steam_cover(STEAM_APPID)

    assert cover.endswith("/steam/apps/%s/library_600x900_2x.jpg" % STEAM_APPID)


def test_every_cdn_is_tried_for_a_cover(reachable):
    # One CDN being down should not cost the cover.
    assert steamlookups.get_steam_cover(STEAM_APPID) is None
    assert len(reachable["probed"]) == len(config.ContentDeliveryNetworkType.members())


def test_a_cover_stops_at_the_first_cdn_that_answers(reachable):
    first = config.ContentDeliveryNetworkType.members()[0]
    reachable["ok"].add(
        "https://cdn.%s.steamstatic.com/steam/apps/%s/library_600x900_2x.jpg"
        % (first.lower(), STEAM_APPID))

    steamlookups.get_steam_cover(STEAM_APPID)

    assert len(reachable["probed"]) == 1


def test_a_trailer_is_scraped_from_the_store_page(reachable, monkeypatch):
    reachable["all"] = True
    monkeypatch.setattr(
        steamlookups.webpage, "get_matching_url",
        lambda **kwargs: "https://video.cdn.steamstatic.com/store_trailers/movie.mp4")

    assert steamlookups.get_steam_trailer(STEAM_APPID).endswith(".mp4")


def test_a_trailer_is_looked_for_as_a_video_file(reachable, monkeypatch):
    reachable["all"] = True
    seen = {}

    def get_matching_url(**kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(steamlookups.webpage, "get_matching_url", get_matching_url)
    steamlookups.get_steam_trailer(STEAM_APPID)

    assert seen["ends_with"] == ".mp4"
    assert seen["starts_with"].startswith("https://video.")


def test_no_trailer_anywhere_is_nothing(reachable, monkeypatch):
    reachable["all"] = True
    monkeypatch.setattr(steamlookups.webpage, "get_matching_url", lambda **kwargs: None)

    assert steamlookups.get_steam_trailer(STEAM_APPID) is None


###########################################################
# Matching a game to an appid
###########################################################

@pytest.fixture
def appid_list(monkeypatch):
    # Stands in for the downloaded appid csv.
    state = {"rows": []}
    monkeypatch.setattr(
        steamlookups.programs, "get_tool_path_config_value", lambda tool, key: "/tools/appids.csv")
    monkeypatch.setattr(
        steamlookups.serialization, "read_csv_file", lambda **kwargs: state["rows"])
    return state


def row(appid, title):
    return {config.search_result_key_id: appid, config.search_result_key_title: title}


def test_a_matching_title_is_found(appid_list):
    appid_list["rows"] = [row("220", "Half-Life 2")]

    results = steamlookups.find_steam_appid_matches("Half-Life 2")

    assert [result.get_id() for result in results] == ["220"]


def test_an_unrelated_title_is_not_matched(appid_list):
    appid_list["rows"] = [row("220", "Half-Life 2"), row("400", "Portal")]

    results = steamlookups.find_steam_appid_matches("Half-Life 2")

    assert [result.get_title() for result in results] == ["Half-Life 2"]


def test_a_match_carries_how_close_it_was(appid_list):
    appid_list["rows"] = [row("220", "Half-Life 2")]

    assert steamlookups.find_steam_appid_matches("Half-Life 2")[0].get_relevance() > 0


def test_an_empty_list_matches_nothing(appid_list):
    assert steamlookups.find_steam_appid_matches("Half-Life 2") == []


def test_the_closest_match_with_a_live_page_is_taken(appid_list, reachable):
    # The csv carries every appid Steam ever had, including delisted ones.
    reachable["all"] = True
    appid_list["rows"] = [row("220", "Half-Life 2"), row("219", "Half-Life 2 Demo")]

    assert steamlookups.find_steam_appid_match("Half-Life 2").get_id() == "220"


def test_a_delisted_match_is_passed_over(appid_list, reachable):
    # The csv keeps delisted appids, and the closest title is often the one
    # whose page is gone.
    appid_list["rows"] = [row("220", "Half-Life 2"), row("219", "Half Life 2")]
    reachable["ok"].add("https://store.steampowered.com/app/219")

    assert steamlookups.find_steam_appid_match("Half-Life 2").get_id() == "219"


def test_no_live_page_anywhere_matches_nothing(appid_list, reachable):
    appid_list["rows"] = [row("220", "Half-Life 2")]

    assert steamlookups.find_steam_appid_match("Half-Life 2") is None


def test_the_page_check_can_be_skipped(appid_list, reachable):
    appid_list["rows"] = [row("220", "Half-Life 2")]

    assert steamlookups.find_steam_appid_match(
        "Half-Life 2", only_active_pages = False).get_id() == "220"
    assert reachable["probed"] == []


def test_skipping_the_page_check_still_takes_the_closest(appid_list, reachable):
    appid_list["rows"] = [row("219", "Half Life 2"), row("220", "Half-Life 2")]

    assert steamlookups.find_steam_appid_match("Half-Life 2", only_active_pages = False).get_id() == "220"


def test_nothing_to_match_yields_nothing(appid_list, reachable):
    assert steamlookups.find_steam_appid_match("Half-Life 2") is None


###########################################################
# Finding assets for a game
###########################################################

def test_a_cover_is_found_for_a_matched_game(appid_list, reachable):
    reachable["all"] = True
    appid_list["rows"] = [row("220", "Half-Life 2")]

    results = steamlookups.find_steam_assets("Half-Life 2", config.AssetType.BOXFRONT)

    assert len(results) == 1
    assert results[0].get_url().endswith("library_600x900_2x.jpg")


def test_a_video_is_found_for_a_matched_game(appid_list, reachable, monkeypatch):
    reachable["all"] = True
    appid_list["rows"] = [row("220", "Half-Life 2")]
    monkeypatch.setattr(
        steamlookups.webpage, "get_matching_url",
        lambda **kwargs: "https://video.cdn.steamstatic.com/store_trailers/movie.mp4")

    results = steamlookups.find_steam_assets("Half-Life 2", config.AssetType.VIDEO)

    assert results[0].get_url().endswith(".mp4")


def test_a_game_that_cannot_be_matched_has_no_assets(appid_list, reachable):
    assert steamlookups.find_steam_assets("Half-Life 2", config.AssetType.BOXFRONT) == []


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

    assert steamlookups.find_steam_assets("Half-Life 2", asset_type) == []


###########################################################
# SteamGridDB covers
###########################################################

def grid(url, width = 600, height = 900):
    return types.SimpleNamespace(url = url, width = str(width), height = str(height))


@pytest.fixture
def griddb(monkeypatch, isolated_settings):
    state = {"games": [], "grids": {}, "searched": [], "key": None}
    isolated_settings.set_value("UserData.Scraping", "steamgriddb_api_key", "gridkey")

    class SteamGridDB:
        def __init__(self, api_key):
            state["key"] = api_key
        def search_game(self, term):
            state["searched"].append(term)
            return state["games"]
        def get_grids_by_gameid(self, game_ids):
            return state["grids"].get(game_ids[0])

    monkeypatch.setattr(steamlookups.programs, "get_tool_path_config_value", lambda tool, key: "/tools/sgdb")
    monkeypatch.setattr(steamlookups.programs, "get_tool_config_value", lambda tool, key: "steamgrid")
    monkeypatch.setattr(steamlookups.modules, "import_python_module_package",
        lambda module_path, module_name: types.SimpleNamespace(SteamGridDB = SteamGridDB))
    monkeypatch.setattr(steamlookups.image, "get_image_format", lambda url: url.rsplit(".", 1)[-1])
    return state


def add_game(griddb, game_id, name, grids):
    griddb["games"].append(types.SimpleNamespace(id = game_id, name = name, release_date = "2004"))
    griddb["grids"][game_id] = grids


def test_covers_are_found_and_ranked(griddb):
    add_game(griddb, 1, "Half-Life 2", [grid("a.png")])
    add_game(griddb, 2, "Half-Life 2 Episode One", [grid("b.png")])
    add_game(griddb, 3, "Portal", [grid("c.png")])

    results = steamlookups.find_steam_griddb_covers("Half-Life 2")

    assert griddb["key"] == "gridkey"
    assert griddb["searched"] == ["Half-Life+2"]
    assert results[0].get_url() == "a.png"
    assert results[0].get_description() == "Half-Life 2 (2004)"
    assert (results[0].get_width(), results[0].get_height()) == (600, 900)
    assert "c.png" not in [result.get_url() for result in results]


def test_covers_can_be_limited_by_size_and_type(griddb):
    add_game(griddb, 1, "Half-Life 2", [grid("a.png"), grid("b.png", 920, 430), grid("c.jpg")])

    by_size = steamlookups.find_steam_griddb_covers("Half-Life 2", image_dimensions = [920, 430])
    by_type = steamlookups.find_steam_griddb_covers("Half-Life 2", image_types = ["png"])

    assert [result.get_url() for result in by_size] == ["b.png"]
    assert sorted(result.get_url() for result in by_type) == ["a.png", "b.png"]


def test_a_game_without_grids_gives_no_covers(griddb):
    add_game(griddb, 1, "Half-Life 2", None)

    assert steamlookups.find_steam_griddb_covers("Half-Life 2") == []
