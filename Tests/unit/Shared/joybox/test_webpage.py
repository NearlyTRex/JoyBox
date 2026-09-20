# Imports
import pytest

# Local imports
from joybox import webpage

pytest.importorskip("bs4")
By = pytest.importorskip("selenium.webdriver.common.by").By


###########################################################
# Page parsing
#
# Store scrapers read metadata out of whatever the page hands back, so a parse
# that quietly returns None looks the same as a page with nothing in it.
###########################################################

HTML = """
<html><body>
  <div class="game" id="main">
    <h1>Chrono Trigger</h1>
    <a href="/game/1">Details</a>
  </div>
</body></html>
"""

XML = """<?xml version="1.0"?>
<catalog><game id="1"><title>Chrono Trigger</title></game></catalog>
"""


def test_html_is_parsed():
    soup = webpage.parse_html_page_source(HTML)

    assert soup is not None
    assert soup.find("h1").text == "Chrono Trigger"


def test_xml_is_parsed():
    soup = webpage.parse_xml_page_source(XML)

    assert soup is not None
    assert soup.find("title").text == "Chrono Trigger"


def test_an_xml_attribute_is_read():
    soup = webpage.parse_xml_page_source(XML)

    assert soup.find("game")["id"] == "1"


def test_empty_content_parses_to_an_empty_document():
    soup = webpage.parse_html_page_source("")

    assert soup is not None
    assert soup.find("h1") is None


def test_malformed_html_still_parses():
    # Store pages are rarely well formed; refusing them would lose every field.
    soup = webpage.parse_html_page_source("<div><p>text<div>")

    assert soup is not None
    assert "text" in soup.get_text()


def test_an_unknown_parser_yields_nothing():
    assert webpage.parse_page_source(HTML, features = "not-a-parser") is None


def test_a_missing_element_is_absent():
    soup = webpage.parse_html_page_source(HTML)

    assert soup.find("table") is None


###########################################################
# Element locators
#
# Each locator maps one key to a selenium By constant. A key mapped to the
# wrong constant searches the page by the wrong axis and finds nothing.
###########################################################

@pytest.mark.parametrize("key,expected", [
    ("id", By.ID),
    ("name", By.NAME),
    ("class", By.CLASS_NAME),
    ("tag", By.TAG_NAME),
    ("xpath", By.XPATH),
    ("css_selector", By.CSS_SELECTOR),
    ("link_text", By.LINK_TEXT),
    ("partial_link_text", By.PARTIAL_LINK_TEXT),
])
def test_every_locator_key_maps_to_its_strategy(key, expected):
    locator = webpage.ElementLocator({key: "value"})

    assert locator.get() == (expected, "value")


def test_locator_strategies_are_distinct():
    keys = ["id", "name", "class", "tag", "xpath", "css_selector", "link_text",
            "partial_link_text"]
    strategies = [webpage.ElementLocator({key: "value"}).get()[0] for key in keys]

    assert len(set(strategies)) == len(keys)


def test_a_locator_value_is_carried_through():
    assert webpage.ElementLocator({"css_selector": "div.game > h1"}).get()[1] == "div.game > h1"


def test_an_unknown_locator_key_is_refused():
    with pytest.raises(ValueError):
        webpage.ElementLocator({"colour": "red"})


def test_a_locator_with_two_keys_is_refused():
    # Two keys would silently use whichever the dict yielded first.
    with pytest.raises(ValueError):
        webpage.ElementLocator({"id": "main", "class": "game"})


def test_an_empty_locator_is_refused():
    with pytest.raises(ValueError):
        webpage.ElementLocator({})


@pytest.mark.parametrize("info", ["id", ["id", "main"], None, 1])
def test_a_non_dictionary_locator_is_refused(info):
    with pytest.raises(ValueError):
        webpage.ElementLocator(info)


###########################################################
# Element readers
#
# These take whatever selenium hands back, including None when a wait timed
# out, so none of them may raise.
###########################################################

class FakeElement:

    def __init__(self, text = "", attributes = None):
        self.text = text
        self.attributes = attributes or {}

    def get_attribute(self, name):
        return self.attributes.get(name)


class BrokenElement:

    @property
    def text(self):
        raise RuntimeError("stale element")

    def get_attribute(self, name):
        raise RuntimeError("stale element")


def test_element_text_is_read():
    assert webpage.get_element_text(FakeElement(text = "Chrono Trigger")) == "Chrono Trigger"


def test_a_missing_element_has_no_text():
    assert webpage.get_element_text(None) is None


def test_a_stale_element_has_no_text():
    assert webpage.get_element_text(BrokenElement()) is None


def test_an_attribute_is_read():
    element = FakeElement(attributes = {"href": "/game/1"})

    assert webpage.get_element_attribute(element, "href") == "/game/1"


def test_a_missing_attribute_is_absent():
    assert webpage.get_element_attribute(FakeElement(), "href") is None


def test_a_missing_element_has_no_attribute():
    assert webpage.get_element_attribute(None, "href") is None


@pytest.mark.parametrize("name", [None, "", 1, ["href"]])
def test_an_invalid_attribute_name_is_refused(name):
    element = FakeElement(attributes = {"href": "/game/1"})

    assert webpage.get_element_attribute(element, name) is None


def test_a_stale_element_has_no_attribute():
    assert webpage.get_element_attribute(BrokenElement(), "href") is None


def test_children_text_is_extracted_from_inner_html():
    element = FakeElement(attributes = {"innerHTML": "<p>Chrono&nbsp;Trigger</p>"})

    assert "Chrono" in webpage.get_element_children_text(element)


def test_an_element_without_inner_html_has_no_children_text():
    assert webpage.get_element_children_text(FakeElement()) is None


def test_a_missing_element_has_no_children_text():
    assert webpage.get_element_children_text(None) is None


def test_a_stale_element_has_no_children_text():
    assert webpage.get_element_children_text(BrokenElement()) is None


def test_a_missing_element_has_no_link_url():
    assert webpage.get_element_link_url(None) is None


###########################################################
# Cookie files
###########################################################

def test_a_cookie_file_is_placed_in_the_cookie_directory(monkeypatch):
    monkeypatch.setattr(webpage.runtime, "get_cookie_directory", lambda: "/home/user/.cookies")

    assert webpage.get_cookie_file("gog").startswith("/home/user/.cookies")


def test_a_cookie_file_is_named_after_its_site(monkeypatch):
    monkeypatch.setattr(webpage.runtime, "get_cookie_directory", lambda: "/cookies")
    path = webpage.get_cookie_file("gog")

    assert "gog" in path
    assert path.endswith(webpage.config.cookie_suffix_path)


def test_two_sites_get_distinct_cookie_files(monkeypatch):
    monkeypatch.setattr(webpage.runtime, "get_cookie_directory", lambda: "/cookies")

    assert webpage.get_cookie_file("gog") != webpage.get_cookie_file("humblebundle")


###########################################################
# Driver sessions
#
# A scrape runs against a browser that can die mid-run. Every helper has to
# survive a dead session rather than raising out through the scraper.
###########################################################

import json
import os


class FakeDriver:

    def __init__(self, url = "https://example.com/", cookies = None, dead = False):
        self._url = url
        self._cookies = cookies if cookies is not None else []
        self.dead = dead
        self.visited = []
        self.scripts = []
        self.added_cookies = []
        self.quit_calls = 0
        self.page_source = "<html><body>page</body></html>"

    @property
    def current_url(self):
        if self.dead:
            raise RuntimeError("session deleted")
        return self._url

    def get(self, url):
        if self.dead:
            raise RuntimeError("session deleted")
        self.visited.append(url)
        self._url = url

    def get_cookies(self):
        if self.dead:
            raise RuntimeError("session deleted")
        return self._cookies

    def add_cookie(self, cookie):
        if not isinstance(cookie, dict) or "name" not in cookie:
            raise ValueError("bad cookie")
        self.added_cookies.append(cookie)

    def execute_script(self, script):
        if self.dead:
            raise RuntimeError("session deleted")
        self.scripts.append(script)

    def close(self):
        if self.dead:
            raise RuntimeError("session deleted")

    def quit(self):
        self.quit_calls += 1


###########################################################
# Session validity
###########################################################

def test_a_live_driver_has_a_valid_session():
    assert webpage.is_session_valid(FakeDriver()) is True


def test_a_dead_driver_has_no_valid_session():
    assert webpage.is_session_valid(FakeDriver(dead = True)) is False


def test_no_driver_has_no_valid_session():
    assert webpage.is_session_valid(None) is False


def test_an_object_without_a_url_is_still_valid():
    # Elements are passed through the same check and have no current_url.
    class Bare:
        pass

    assert webpage.is_session_valid(Bare()) is True


###########################################################
# Navigation
###########################################################

def test_a_url_is_loaded():
    driver = FakeDriver()

    assert webpage.load_url(driver, "https://store.example/game") is True
    assert driver.visited == ["https://store.example/game"]


def test_a_dead_session_loads_nothing():
    driver = FakeDriver(dead = True)

    assert webpage.load_url(driver, "https://store.example/game") is False
    assert driver.visited == []


@pytest.mark.parametrize("url", [None, "", 12345, ["https://x"]])
def test_an_invalid_url_is_refused(url):
    driver = FakeDriver()

    assert webpage.load_url(driver, url) is False
    assert driver.visited == []


def test_pretending_navigates_nowhere():
    driver = FakeDriver()

    assert webpage.load_url(driver, "https://x", pretend_run = True) is True
    assert driver.visited == []


def test_the_current_url_is_read():
    assert webpage.get_current_page_url(FakeDriver(url = "https://a/b")) == "https://a/b"


def test_a_dead_session_has_no_current_url():
    assert webpage.get_current_page_url(FakeDriver(dead = True)) is None


def test_a_loaded_url_is_recognised():
    driver = FakeDriver(url = "https://store.example/game?id=1")

    assert webpage.is_url_loaded(driver, "https://store.example/game") is True


def test_a_different_url_is_not_loaded():
    # A redirect to a login page is the case this catches.
    driver = FakeDriver(url = "https://store.example/login")

    assert webpage.is_url_loaded(driver, "https://store.example/game") is False


def test_a_dead_session_has_nothing_loaded():
    assert webpage.is_url_loaded(FakeDriver(dead = True), "https://x") is False


@pytest.mark.parametrize("url", [None, "", 12345])
def test_an_invalid_url_is_never_loaded(url):
    assert webpage.is_url_loaded(FakeDriver(), url) is False


###########################################################
# Scrolling and source
###########################################################

def test_scrolling_runs_the_scroll_script():
    driver = FakeDriver()

    assert webpage.scroll_to_end_of_page(driver) is True
    assert "scrollHeight" in driver.scripts[0]


def test_a_dead_session_does_not_scroll():
    driver = FakeDriver(dead = True)

    assert webpage.scroll_to_end_of_page(driver) is False
    assert driver.scripts == []


def test_pretending_does_not_scroll():
    driver = FakeDriver()
    webpage.scroll_to_end_of_page(driver, pretend_run = True)

    assert driver.scripts == []


###########################################################
# Cookies
#
# A saved session is what avoids logging into a store on every scrape.
###########################################################

COOKIES = [
    {"name": "session", "value": "abc123", "domain": ".example.com"},
    {"name": "prefs", "value": "dark", "domain": ".example.com"},
]


def test_cookies_are_saved(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    driver = FakeDriver(cookies = COOKIES)

    assert webpage.save_cookie(driver, str(target)) is True
    assert json.loads(target.read_text()) == COOKIES


def test_saving_creates_the_cookie_directory(tmp_path):
    target = tmp_path / "nested" / ("store" + webpage.config.cookie_suffix_path)
    webpage.save_cookie(FakeDriver(cookies = COOKIES), str(target))

    assert target.exists()


def test_no_cookies_saves_nothing(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)

    assert webpage.save_cookie(FakeDriver(cookies = []), str(target)) is False
    assert not target.exists()


def test_a_dead_session_saves_no_cookies(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)

    assert webpage.save_cookie(FakeDriver(dead = True), str(target)) is False
    assert not target.exists()


@pytest.mark.parametrize("path", [None, ""])
def test_an_invalid_cookie_path_is_refused(path):
    assert webpage.save_cookie(FakeDriver(cookies = COOKIES), path) is False


def test_cookies_are_loaded(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    target.write_text(json.dumps(COOKIES))
    driver = FakeDriver()

    assert webpage.load_cookie(driver, str(target)) is True
    assert driver.added_cookies == COOKIES


def test_a_missing_cookie_file_loads_nothing(tmp_path):
    driver = FakeDriver()

    assert webpage.load_cookie(driver, str(tmp_path / "absent.cookie")) is False
    assert driver.added_cookies == []


def test_a_cookie_file_that_is_not_a_list_is_refused(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    target.write_text(json.dumps({"name": "session"}))

    assert webpage.load_cookie(FakeDriver(), str(target)) is False


def test_one_bad_cookie_does_not_stop_the_rest(tmp_path):
    # An expired or malformed cookie should not cost the whole session.
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    target.write_text(json.dumps([{"bad": "cookie"}] + COOKIES))
    driver = FakeDriver()

    assert webpage.load_cookie(driver, str(target)) is True
    assert driver.added_cookies == COOKIES


def test_a_dead_session_loads_no_cookies(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    target.write_text(json.dumps(COOKIES))
    driver = FakeDriver(dead = True)

    assert webpage.load_cookie(driver, str(target)) is False
    assert driver.added_cookies == []


def test_pretending_loads_no_cookies(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    target.write_text(json.dumps(COOKIES))
    driver = FakeDriver()
    webpage.load_cookie(driver, str(target), pretend_run = True)

    assert driver.added_cookies == []


def test_cookies_survive_a_save_and_load(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    webpage.save_cookie(FakeDriver(cookies = COOKIES), str(target))
    driver = FakeDriver()
    webpage.load_cookie(driver, str(target))

    assert driver.added_cookies == COOKIES


###########################################################
# Teardown
###########################################################

def test_a_driver_is_destroyed():
    driver = FakeDriver()

    assert webpage.destroy_web_driver(driver) is True
    assert driver.quit_calls == 1


def test_destroying_nothing_is_harmless():
    assert webpage.destroy_web_driver(None) in (True, False)


def test_a_driver_that_fails_to_quit_is_handled():
    class Stubborn(FakeDriver):
        def quit(self):
            raise RuntimeError("already gone")

    assert webpage.destroy_web_driver(Stubborn()) is False


def test_the_generated_cookie_path_is_one_that_can_be_read(tmp_path, monkeypatch):
    # Cookies are written and read as json, and read_json_file refuses a file
    # whose extension does not say so.
    monkeypatch.setattr(webpage.runtime, "get_cookie_directory", lambda: str(tmp_path))
    target = webpage.get_cookie_file("steam")

    assert webpage.save_cookie(FakeDriver(cookies = COOKIES), target) is True
    driver = FakeDriver()
    assert webpage.load_cookie(driver, target) is True
    assert driver.added_cookies == COOKIES
