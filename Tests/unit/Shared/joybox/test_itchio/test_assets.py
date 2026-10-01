# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import itchio
from itchio_helpers import FakeElement, GAME_URL, game_cell

COVER = "https://img.itch.zone/cover.png"


def add_results(browser, *cells):
    return browser.add(FakeElement("browse_game_grid", children = cells))


###########################################################
# Box front
###########################################################

def test_the_cover_comes_from_the_matching_search_result(itchio_store, browser):
    add_results(browser,
        game_cell(url = "https://other.itch.io/cool-game", cover = "https://img.itch.zone/wrong.png"),
        game_cell(cover = COVER),
        game_cell(cover = "https://img.itch.zone/later.png"))

    url = itchio_store.get_latest_asset_url(GAME_URL, config.AssetType.BOXFRONT)

    assert url == COVER
    assert browser.loaded == [("https://itch.io/search?q=cool-game", itchio_store.get_cookie_file())]
    assert browser.connects == [True]
    assert browser.disconnected == [browser.page]


def test_results_without_a_title_or_cover_are_passed_over(itchio_store, browser):
    add_results(browser, game_cell(title = None), game_cell(cover = None))

    assert itchio_store.get_latest_asset_url(GAME_URL, config.AssetType.BOXFRONT) is None
    assert browser.disconnected == [browser.page]


def test_no_matching_result_gives_no_cover(itchio_store, browser):
    add_results(browser, game_cell(url = "https://other.itch.io/cool-game"))

    assert itchio_store.get_latest_asset_url(GAME_URL, config.AssetType.BOXFRONT) is None


def test_an_empty_search_gives_no_cover(itchio_store, browser):
    add_results(browser)

    assert itchio_store.get_latest_asset_url(GAME_URL, config.AssetType.BOXFRONT) is None
    assert browser.disconnected == [browser.page]


def test_a_search_that_will_not_load_closes_the_browser(itchio_store, browser):
    add_results(browser, game_cell())
    browser.load_ok = False

    assert itchio_store.get_latest_asset_url(GAME_URL, config.AssetType.BOXFRONT) is None
    assert browser.disconnected == [browser.page]


def test_a_page_without_results_closes_the_browser(itchio_store, browser):
    assert itchio_store.get_latest_asset_url(GAME_URL, config.AssetType.BOXFRONT) is None
    assert browser.disconnected == [browser.page]


def test_a_search_that_raises_still_closes_the_browser_once(itchio_store, browser):
    browser.load_error = RuntimeError("session lost")

    with pytest.raises(RuntimeError):
        itchio_store.get_latest_asset_url(GAME_URL, config.AssetType.BOXFRONT)
    assert browser.disconnected == [browser.page]


def test_no_browser_gives_no_cover(itchio_store, browser):
    browser.connect_ok = False

    assert itchio_store.get_latest_asset_url(GAME_URL, config.AssetType.BOXFRONT) is None


def test_a_browser_that_will_not_close_gives_no_cover(itchio_store, browser):
    add_results(browser, game_cell())
    browser.disconnect_ok = False

    assert itchio_store.get_latest_asset_url(GAME_URL, config.AssetType.BOXFRONT) is None


###########################################################
# Video and others
###########################################################

def test_the_video_is_the_embedded_youtube_link(itchio_store, browser, monkeypatch):
    seen = {}

    def get_matching_url(**kwargs):
        seen.update(kwargs)
        return "https://www.youtube.com/embed/abc"
    monkeypatch.setattr(itchio.webpage, "get_matching_url", get_matching_url)

    url = itchio_store.get_latest_asset_url(GAME_URL, config.AssetType.VIDEO)

    assert url == "https://www.youtube.com/embed/abc"
    assert seen["url"] == GAME_URL
    assert seen["starts_with"] == "https://www.youtube.com/embed"
    assert browser.connects == []


def test_other_asset_types_have_no_source(itchio_store, browser):
    assert itchio_store.get_latest_asset_url(GAME_URL, config.AssetType.BACKGROUND) is None
    assert browser.connects == []


@pytest.mark.parametrize("asset_type", [config.AssetType.BOXFRONT, config.AssetType.VIDEO])
def test_an_invalid_identifier_looks_nothing_up(itchio_store, browser, asset_type):
    assert itchio_store.get_latest_asset_url("", asset_type) is None
    assert browser.connects == []
