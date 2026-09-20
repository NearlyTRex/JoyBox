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
