# Third-party imports
import pytest

# Local imports
from itchio_helpers import FakeElement, GAME_URL


def add_details(browser, *lines):
    browser.add(FakeElement("game_info_panel_widget", text = "\n".join(lines)))


###########################################################
# Game page metadata
###########################################################

def test_the_description_and_details_are_read(itchio_store, browser):
    browser.add(FakeElement("formatted_description", text = "A game about things."))
    add_details(browser,
        "Updated Jan 01, 2022",
        "Release date Mar 03, 2021",
        "Authors Maker, Helper",
        "Genre Puzzle, Platformer",
        "Tags pixel-art")

    entry = itchio_store.get_latest_metadata(GAME_URL)

    assert browser.loaded == [(GAME_URL, itchio_store.get_cookie_file())]
    assert browser.connects == [True]
    assert entry.get_description() == ["A game about things."]
    assert entry.get_release() == "2021-03-03"
    assert entry.get_developer() == "Maker, Helper"
    assert entry.get_publisher() == "Maker, Helper"
    assert entry.get_genre() == "Puzzle;Platformer"


def test_a_single_author_is_both_developer_and_publisher(itchio_store, browser):
    add_details(browser, "Author Maker")

    entry = itchio_store.get_latest_metadata(GAME_URL)

    assert (entry.get_developer(), entry.get_publisher()) == ("Maker", "Maker")


def test_the_published_date_stands_in_for_a_release_date(itchio_store, browser):
    add_details(browser, "Published Feb 14, 2020")

    assert itchio_store.get_latest_metadata(GAME_URL).get_release() == "2020-02-14"


def test_more_information_is_expanded_before_reading(itchio_store, browser):
    link = browser.add(FakeElement("toggle_row", text = "More information"))

    itchio_store.get_latest_metadata(GAME_URL)

    assert link.clicks == 1
    assert browser.slept == [3]


def test_a_page_without_more_information_is_read_as_is(itchio_store, browser):
    itchio_store.get_latest_metadata(GAME_URL)

    assert browser.slept == []


def test_a_bare_page_gives_an_empty_entry(itchio_store, browser):
    browser.add(FakeElement("formatted_description", text = ""))
    browser.add(FakeElement("game_info_panel_widget", text = ""))

    entry = itchio_store.get_latest_metadata(GAME_URL)

    assert entry is not None
    assert entry.get_description() is None
    assert entry.get_release() is None
    assert entry.get_developer() is None
    assert entry.get_genre() is None


def test_the_browser_is_closed_once_after_a_read(itchio_store, browser):
    itchio_store.get_latest_metadata(GAME_URL)

    assert browser.disconnected == [browser.page]


def test_a_page_that_will_not_load_is_retried_then_given_up(itchio_store, browser):
    browser.load_ok = False

    assert itchio_store.get_latest_metadata(GAME_URL, verbose = True) is None
    assert len(browser.loaded) == 3
    assert len(browser.connects) == 3
    assert len(browser.disconnected) == 3


def test_a_failed_attempt_then_a_good_one_closes_each_browser_once(itchio_store, browser, monkeypatch):
    attempts = []
    load = browser.load

    def flaky(url, cookie):
        attempts.append(url)
        if len(attempts) == 1:
            raise RuntimeError("session lost")
        load(url, cookie)
    monkeypatch.setattr(browser, "load", flaky)

    assert itchio_store.get_latest_metadata(GAME_URL) is not None
    assert len(browser.connects) == 2
    assert len(browser.disconnected) == 2


def test_an_interrupted_read_still_disconnects_its_browser_once(itchio_store, browser, monkeypatch):
    def interrupt(url, cookie):
        raise KeyboardInterrupt()
    monkeypatch.setattr(browser, "load", interrupt)

    with pytest.raises(KeyboardInterrupt):
        itchio_store.get_latest_metadata(GAME_URL)
    assert len(browser.disconnected) == 1


def test_no_browser_gives_no_metadata(itchio_store, browser):
    browser.connect_ok = False

    assert itchio_store.get_latest_metadata(GAME_URL) is None
    assert browser.disconnected == []


@pytest.mark.parametrize("identifier", ["", None])
def test_an_invalid_identifier_opens_no_browser(itchio_store, browser, identifier):
    assert itchio_store.get_latest_metadata(identifier) is None
    assert browser.connects == []
