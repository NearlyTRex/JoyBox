# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import legacy
from legacy_helpers import GAME_URL, SEARCH_URL, result_cell


###########################################################
# Store page search
###########################################################

def test_the_closest_titled_result_links_to_the_store_page(legacy_store, browser):
    browser.add(
        result_cell("Mystery Case Files: Dire Grove", "https://www.bigfishgames.com/other/"),
        result_cell("Mystery Case Files"),
        result_cell("Hidden Expedition", "https://www.bigfishgames.com/third/"))

    url = legacy_store.get_latest_url("Mystery Case Files")

    assert url == GAME_URL
    assert browser.connects == [True]
    assert browser.loaded == [SEARCH_URL + "Mystery+Case+Files"]
    assert browser.waits == [15]
    assert browser.closed() == browser.drivers


def test_the_search_terms_are_trimmed_and_encoded(legacy_store, browser):
    browser.add(result_cell())

    legacy_store.get_latest_url("  Drawn & Dark  ")

    assert browser.loaded == [SEARCH_URL + "Drawn+%26+Dark"]


def test_results_without_a_title_are_not_considered(legacy_store, browser):
    browser.add(
        result_cell(title = None, href = "https://www.bigfishgames.com/untitled/"),
        result_cell(title = "", href = "https://www.bigfishgames.com/blank/"),
        result_cell("Mystery Case Files"))

    assert legacy_store.get_latest_url("Mystery Case Files") == GAME_URL


def test_a_best_match_without_a_link_falls_back_to_the_next_best(legacy_store, browser):
    browser.add(
        result_cell("Mystery Case Files", href = None),
        result_cell("Mystery Case Files Two", href = ""),
        result_cell("Mystery Files", "https://www.bigfishgames.com/fallback/?x=1"))

    assert legacy_store.get_latest_url("Mystery Case Files") == "https://www.bigfishgames.com/fallback/"


@pytest.mark.parametrize("cells", [[], [result_cell(title = None), result_cell(href = None)]])
def test_no_usable_result_gives_no_url_without_retrying(legacy_store, browser, cells):
    browser.add(*cells)

    assert legacy_store.get_latest_url("Mystery Case Files") is None
    assert len(browser.connects) == 1
    assert browser.closed() == browser.drivers


def test_a_search_with_no_results_page_is_not_retried(legacy_store, browser):
    browser.has_results = False

    assert legacy_store.get_latest_url("Mystery Case Files") is None
    assert len(browser.connects) == 1
    assert browser.slept == []
    assert browser.closed() == browser.drivers


@pytest.mark.parametrize("identifier", ["", None, 5])
def test_an_invalid_identifier_opens_no_browser(legacy_store, browser, identifier):
    assert legacy_store.get_latest_url(identifier) is None
    assert browser.connects == []


def test_a_failed_load_is_retried_with_a_fresh_browser(legacy_store, browser):
    browser.add(result_cell())
    browser.failed_loads = 2

    assert legacy_store.get_latest_url("Mystery Case Files") == GAME_URL
    assert len(browser.drivers) == 3
    assert browser.slept == [2, 4]
    assert browser.closed() == browser.drivers


def test_every_browser_is_closed_exactly_once_when_all_attempts_fail(legacy_store, browser):
    browser.add(result_cell())
    browser.failed_loads = 3

    assert legacy_store.get_latest_url("Mystery Case Files") is None
    assert len(browser.drivers) == 3
    assert browser.closed() == browser.drivers
    assert browser.slept == [2, 4]


def test_a_browser_that_will_not_start_is_retried_then_given_up(legacy_store, browser):
    browser.failed_connects = 3

    assert legacy_store.get_latest_url("Mystery Case Files") is None
    assert browser.connects == [True, True, True]
    assert browser.disconnected == []


def test_a_browser_that_starts_on_retry_is_used_and_closed(legacy_store, browser):
    browser.add(result_cell())
    browser.failed_connects = 1

    assert legacy_store.get_latest_url("Mystery Case Files") == GAME_URL
    assert browser.closed() == browser.drivers
    assert len(browser.drivers) == 1


def test_an_empty_retry_after_a_failure_is_retried_again(legacy_store, browser):
    browser.has_results = False
    browser.failed_loads = 1

    assert legacy_store.get_latest_url("Mystery Case Files") is None
    assert len(browser.drivers) == 3
    assert browser.closed() == browser.drivers


def test_the_browser_is_closed_with_the_callers_run_flags(legacy_store, browser):
    browser.add(result_cell())

    legacy_store.get_latest_url("Mystery Case Files", pretend_run = True)

    assert browser.disconnected == [(browser.drivers[0], True)]


def test_an_interrupted_search_still_closes_the_browser_once(legacy_store, browser, monkeypatch):
    browser.add(result_cell())

    def interrupt(element, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(legacy.webpage, "get_element_children_text", interrupt)

    with pytest.raises(KeyboardInterrupt):
        legacy_store.get_latest_url("Mystery Case Files")
    assert browser.closed() == browser.drivers
    assert len(browser.drivers) == 1


###########################################################
# Assets
###########################################################

@pytest.fixture
def asset_lookups(monkeypatch):
    calls = []

    def find_metadata_asset(**kwargs):
        calls.append(("metadata", kwargs))
        return "https://images.example/box.png"

    def get_matching_url(**kwargs):
        calls.append(("page", kwargs))
        return "https://www.youtube.com/embed/abc?enablejsapi=1"

    monkeypatch.setattr(legacy.metadataassetcollector, "find_metadata_asset", find_metadata_asset)
    monkeypatch.setattr(legacy.webpage, "get_matching_url", get_matching_url)
    return calls


def test_the_box_front_is_found_by_game_name(legacy_store, asset_lookups):
    url = legacy_store.get_latest_asset_url(GAME_URL, config.AssetType.BOXFRONT, game_name = "Mystery Case Files")

    assert url == "https://images.example/box.png"
    assert asset_lookups == [("metadata", {
        "game_platform": config.Platform.COMPUTER_LEGACY_GAMES,
        "game_name": "Mystery Case Files",
        "asset_type": config.AssetType.BOXFRONT,
        "verbose": False,
        "pretend_run": False,
        "exit_on_failure": False})]


def test_without_a_game_name_the_box_front_is_found_by_identifier(legacy_store, asset_lookups):
    legacy_store.get_latest_asset_url(GAME_URL, config.AssetType.BOXFRONT)

    assert asset_lookups[0][1]["game_name"] == GAME_URL


def test_the_video_is_the_embedded_youtube_player_on_the_store_page(legacy_store, asset_lookups):
    url = legacy_store.get_latest_asset_url(GAME_URL, config.AssetType.VIDEO, verbose = True)

    assert url == "https://www.youtube.com/embed/abc?enablejsapi=1"
    assert asset_lookups == [("page", {
        "url": GAME_URL,
        "base_url": "https://www.bigfishgames.com",
        "starts_with": "https://www.youtube.com/embed",
        "ends_with": "enablejsapi=1",
        "verbose": True,
        "pretend_run": False,
        "exit_on_failure": False})]


def test_other_asset_types_have_no_url(legacy_store, asset_lookups):
    assert legacy_store.get_latest_asset_url(GAME_URL, config.AssetType.SCREENSHOT) is None
    assert asset_lookups == []


@pytest.mark.parametrize("identifier", ["", None])
def test_an_invalid_asset_identifier_looks_nothing_up(legacy_store, asset_lookups, identifier):
    assert legacy_store.get_latest_asset_url(identifier, config.AssetType.BOXFRONT) is None
    assert asset_lookups == []
