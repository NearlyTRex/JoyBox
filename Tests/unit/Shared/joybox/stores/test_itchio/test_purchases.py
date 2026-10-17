# Imports
import json
import os
import time

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import itchio
from itchio_helpers import FakeElement, GAME_URL, game_cell


@pytest.fixture
def cache_file(tmp_path):
    return tmp_path / "cache" / "itchio_purchases_cache.json"


def summary(purchases):
    return [(
        purchase.get_value(config.json_key_store_appid),
        purchase.get_value(config.json_key_store_appurl),
        purchase.get_value(config.json_key_store_name)) for purchase in purchases]


def write_cache(cache_file, data, hours_old = 0):
    cache_file.parent.mkdir(parents = True, exist_ok = True)
    cache_file.write_text(json.dumps(data))
    stamp = time.time() - hours_old * 3600
    os.utime(cache_file, (stamp, stamp))


###########################################################
# Scraping the purchases page
###########################################################

def test_each_game_cell_becomes_a_purchase(itchio_store, browser):
    browser.add(game_cell())
    browser.add(game_cell(url = "https://other.itch.io/second", title = "Second Game \n", game_id = "99"))

    purchases = itchio_store.get_latest_purchases()

    assert summary(purchases) == [
        ("1234", GAME_URL, "Cool Game"),
        ("99", "https://other.itch.io/second", "Second Game"),
    ]
    assert browser.loaded == [("https://itch.io/my-purchases", itchio_store.get_cookie_file())]
    assert browser.connects == [True]
    assert browser.disconnected == [browser.page]


def test_purchases_carry_the_itchio_platform(itchio_store, browser):
    browser.add(game_cell())

    purchase = itchio_store.get_latest_purchases()[0]

    assert purchase.get_platform() == config.Platform.COMPUTER_ITCHIO


def test_download_links_are_reduced_to_the_game_page(itchio_store, browser):
    browser.add(game_cell(url = GAME_URL + "/download/abcdef"))

    assert summary(itchio_store.get_latest_purchases())[0][1] == GAME_URL


def test_the_page_is_scrolled_until_everything_has_loaded(itchio_store, browser):
    browser.add(game_cell())
    browser.add_loader(scrolls = 3)

    itchio_store.get_latest_purchases()

    assert browser.scrolls == 3


def test_a_purchase_whose_cover_has_not_loaded_still_counts(itchio_store, browser):
    browser.add(game_cell(cover = None))

    assert summary(itchio_store.get_latest_purchases()) == [("1234", GAME_URL, "Cool Game")]


def test_cells_without_a_title_link_are_skipped(itchio_store, browser):
    browser.add(game_cell(title = None))
    browser.add(game_cell(url = None))
    browser.add(game_cell(url = "https://other.itch.io/kept", title = "Kept"))

    assert summary(itchio_store.get_latest_purchases()) == [("1234", "https://other.itch.io/kept", "Kept")]


def test_a_title_without_text_gives_an_empty_name(itchio_store, browser):
    browser.add(game_cell(title = ""))

    assert summary(itchio_store.get_latest_purchases()) == [("1234", GAME_URL, "")]


def test_an_empty_library_gives_no_purchases(itchio_store, browser):
    browser.add(FakeElement("my_collections"))

    assert itchio_store.get_latest_purchases() == []


def test_no_browser_gives_no_purchases(itchio_store, browser):
    browser.connect_ok = False

    assert itchio_store.get_latest_purchases() is None


def test_a_page_that_will_not_load_closes_the_browser(itchio_store, browser, cache_file):
    browser.load_ok = False

    assert itchio_store.get_latest_purchases() is None
    assert browser.disconnected == [browser.page]
    assert not cache_file.exists()


def test_a_scrape_that_raises_still_closes_the_browser_once(itchio_store, browser):
    browser.load_error = RuntimeError("session lost")

    with pytest.raises(RuntimeError):
        itchio_store.get_latest_purchases()
    assert browser.disconnected == [browser.page]


def test_a_browser_that_will_not_close_gives_nothing_and_caches_nothing(itchio_store, browser, cache_file):
    browser.add(game_cell())
    browser.disconnect_ok = False

    assert itchio_store.get_latest_purchases() is None
    assert not cache_file.exists()


###########################################################
# Cache
###########################################################

@pytest.mark.parametrize("verbose", [False, True])
def test_purchases_are_cached_for_a_day(itchio_store, browser, cache_file, verbose):
    browser.add(game_cell())
    itchio_store.get_latest_purchases(verbose = verbose)
    browser.page.children = []

    again = itchio_store.get_latest_purchases(verbose = verbose)

    assert json.loads(cache_file.read_text()) == [{
        config.json_key_store_appid: "1234",
        config.json_key_store_appurl: GAME_URL,
        config.json_key_store_name: "Cool Game"}]
    assert len(browser.connects) == 1
    assert summary(again) == [("1234", GAME_URL, "Cool Game")]
    assert again[0].get_platform() == config.Platform.COMPUTER_ITCHIO


def test_a_day_old_cache_is_refreshed(itchio_store, browser, cache_file):
    write_cache(cache_file, [{config.json_key_store_appid: "1", config.json_key_store_appurl: "old", config.json_key_store_name: "Old"}], hours_old = 25)
    browser.add(game_cell())

    purchases = itchio_store.get_latest_purchases()

    assert summary(purchases) == [("1234", GAME_URL, "Cool Game")]
    assert json.loads(cache_file.read_text())[0][config.json_key_store_appid] == "1234"


def test_a_cached_empty_library_is_still_a_cache_hit(itchio_store, browser, cache_file):
    write_cache(cache_file, [])
    browser.add(game_cell())

    assert itchio_store.get_latest_purchases() == []
    assert browser.connects == []


@pytest.mark.parametrize("contents", ["not json", json.dumps({"not": "a list"}), json.dumps(["not a dict"])])
@pytest.mark.parametrize("verbose", [False, True])
def test_an_unusable_cache_is_refetched(itchio_store, browser, cache_file, contents, verbose):
    cache_file.parent.mkdir(parents = True)
    cache_file.write_text(contents)
    browser.add(game_cell())

    purchases = itchio_store.get_latest_purchases(verbose = verbose)

    assert len(browser.connects) == 1
    assert summary(purchases) == [("1234", GAME_URL, "Cool Game")]


@pytest.mark.parametrize("verbose", [False, True])
def test_a_cache_that_cannot_be_written_still_returns_the_purchases(itchio_store, browser, monkeypatch, verbose):
    browser.add(game_cell())
    monkeypatch.setattr(itchio.serialization, "write_json_file", lambda **kwargs: False)

    assert summary(itchio_store.get_latest_purchases(verbose = verbose)) == [("1234", GAME_URL, "Cool Game")]
