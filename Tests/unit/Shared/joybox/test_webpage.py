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
