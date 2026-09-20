# Third-party imports
import pytest

# Local imports
from joybox import webpage
from webpage_helpers import FakeElement, BrokenElement

pytest.importorskip("bs4")



###########################################################
# Element readers
#
# These take whatever selenium hands back, including None when a wait timed
# out, so none of them may raise.
###########################################################

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
