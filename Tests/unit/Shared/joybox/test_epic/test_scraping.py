# Third-party imports
import pytest

# Local imports
from joybox.stores import epic


###########################################################
# Fake store pages
#
# The store is read through a browser; a page is faked here as a tree of
# elements found by class name or id, each with its text and attributes.
###########################################################

class Element:

    def __init__(self, text = None, **attrs):
        self.text = text
        self.attrs = attrs
        self.children = {}

    def add(self, name, child):
        self.children.setdefault(name, []).append(child)
        return child


class Browser:

    def __init__(self):
        self.root = Element()
        self.loaded = []
        self.load_ok = True
        self.connect_ok = True
        self.connects = 0
        self.disconnected = []


@pytest.fixture
def browser(epic_store, monkeypatch):
    fake = Browser()

    def web_connect(**kwargs):
        fake.connects += 1
        return "driver-%d" % fake.connects if fake.connect_ok else None

    def web_disconnect(web_driver, **kwargs):
        fake.disconnected.append(web_driver)
        return True

    def load_url(driver, url):
        fake.loaded.append(url)
        return fake.load_ok

    def find(parent, locator, all_elements = False):
        element = fake.root if isinstance(parent, str) else parent
        found = element.children.get(locator.by_value, [])
        if all_elements:
            return list(found)
        return found[0] if found else None

    monkeypatch.setattr(epic_store, "web_connect", web_connect)
    monkeypatch.setattr(epic_store, "web_disconnect", web_disconnect)
    monkeypatch.setattr(epic.webpage, "load_url", load_url)
    monkeypatch.setattr(epic.webpage, "wait_for_element", lambda driver, locator, **kwargs: find(driver, locator))
    monkeypatch.setattr(epic.webpage, "get_element",
        lambda parent, locator, all_elements = False, **kwargs: find(parent, locator, all_elements))
    monkeypatch.setattr(epic.webpage, "get_element_children_text", lambda element: element.text if element else None)
    monkeypatch.setattr(epic.webpage, "get_element_attribute", lambda element, name: element.attrs.get(name))
    monkeypatch.setattr(epic.datautils.time, "sleep", lambda seconds: None)
    return fake


###########################################################
# Store page search
###########################################################

def add_result(browser, title, href = None):
    results = browser.root.children.get("css-1ufzxyu")
    container = results[0] if results else browser.root.add("css-1ufzxyu", Element())
    cell = container.add("css-2mlzob", Element())
    cell.add("css-lgj0h8", Element(title))
    if href:
        cell.add("css-1k3j1r9", Element(href = href))


def test_the_closest_title_gives_the_store_page(epic_store, browser):
    add_result(browser, "Hades Soundtrack", "https://store.epicgames.com/p/hades-soundtrack")
    add_result(browser, "Hades", "https://store.epicgames.com/p/hades")

    url = epic_store.get_latest_url(" Hades ")

    assert url == "https://store.epicgames.com/p/hades"
    assert browser.loaded == ["https://store.epicgames.com/en-US/browse?sortBy=relevancy&sortDir=DESC&q=Hades"]
    assert browser.disconnected == ["driver-1"]


def test_search_terms_are_url_encoded(epic_store, browser):
    epic_store.get_latest_url("Tom Clancy's Rainbow Six & Co")

    assert browser.loaded[0].endswith("&q=Tom+Clancy%27s+Rainbow+Six+%26+Co")


def test_a_result_without_a_link_is_passed_over(epic_store, browser):
    add_result(browser, "Hades")
    add_result(browser, "Hades II", "https://store.epicgames.com/p/hades-2")

    assert epic_store.get_latest_url("Hades") == "https://store.epicgames.com/p/hades-2"


def test_no_linked_result_gives_no_url(epic_store, browser):
    add_result(browser, "Hades")

    assert epic_store.get_latest_url("Hades") is None
    assert browser.disconnected == ["driver-1"]


def test_empty_results_give_no_url(epic_store, browser):
    browser.root.add("css-1ufzxyu", Element())

    assert epic_store.get_latest_url("Hades") is None


@pytest.mark.parametrize("load_ok", [False, True])
def test_a_failed_search_still_disconnects(epic_store, browser, load_ok):
    browser.load_ok = load_ok

    assert epic_store.get_latest_url("Hades") is None
    assert browser.disconnected == ["driver-1"]


def test_a_failed_disconnect_keeps_the_url(epic_store, browser, monkeypatch):
    add_result(browser, "Hades", "https://store.epicgames.com/p/hades")
    monkeypatch.setattr(epic_store, "web_disconnect", lambda **kwargs: False)

    assert epic_store.get_latest_url("Hades") == "https://store.epicgames.com/p/hades"


def test_no_browser_gives_no_url(epic_store, browser):
    browser.connect_ok = False

    assert epic_store.get_latest_url("Hades") is None
    assert browser.loaded == []


def test_an_invalid_page_identifier_opens_no_browser(epic_store, browser):
    assert epic_store.get_latest_url("") is None
    assert browser.connects == 0


###########################################################
# Store page metadata
###########################################################

URL = "https://store.epicgames.com/en-US/p/hades"


def add_genres(browser, label, genres):
    section = browser.root.add("css-8f0505", Element(label))
    for genre in genres:
        section.add("css-cyjj8t", Element(genre))


def add_detail(browser, text):
    browser.root.add("css-s97i32", Element(text))


def test_the_description_and_details_are_read(epic_store, browser):
    browser.root.add("about-long-description", Element("A rogue-like dungeon crawler."))
    add_genres(browser, "Features Single Player", ["Single Player"])
    add_genres(browser, "Genres Action Roguelite", ["Action", "", "Roguelite"])
    add_detail(browser, "Developer Supergiant Games")
    add_detail(browser, "Publisher Supergiant Games ")
    add_detail(browser, "Release Date 09/17/20")
    add_detail(browser, "Platform Windows")

    entry = epic_store.get_latest_metadata(URL)

    assert browser.loaded == [URL]
    assert entry.get_description() == ["A rogue-like dungeon crawler."]
    assert entry.get_genre() == "Action;Roguelite"
    assert entry.get_developer() == "Supergiant Games"
    assert entry.get_publisher() == "Supergiant Games"
    assert entry.get_release() == "2020-09-17"
    assert browser.disconnected == ["driver-1"]


def test_an_unreadable_release_date_is_left_unset(epic_store, browser):
    add_detail(browser, "Release Date ")

    assert epic_store.get_latest_metadata(URL).get_release() is None


def test_genre_sections_without_genres_set_none(epic_store, browser):
    add_genres(browser, "Genres", [])
    add_genres(browser, "Genres", [""])
    browser.root.add("css-8f0505", Element(None))

    assert epic_store.get_latest_metadata(URL).get_genre() is None


def test_a_bare_page_gives_an_empty_entry(epic_store, browser):
    browser.root.add("about-long-description", Element(""))
    add_detail(browser, None)

    entry = epic_store.get_latest_metadata(URL)

    assert entry.get_description() is None
    assert entry.get_developer() is None
    assert entry.get_release() is None


def test_a_page_that_will_not_load_is_retried_then_given_up(epic_store, browser):
    browser.load_ok = False

    assert epic_store.get_latest_metadata(URL) is None
    assert len(browser.loaded) == 3
    assert browser.disconnected == ["driver-1", "driver-2", "driver-3"]


def test_a_retry_that_succeeds_disconnects_each_browser_once(epic_store, browser, monkeypatch):
    def load_second_time(driver, url):
        browser.loaded.append(url)
        return len(browser.loaded) > 1
    monkeypatch.setattr(epic.webpage, "load_url", load_second_time)

    assert epic_store.get_latest_metadata(URL) is not None
    assert browser.disconnected == ["driver-1", "driver-2"]


def test_an_interrupted_read_still_disconnects_its_browser_once(epic_store, browser, monkeypatch):
    def load_url(driver, url):
        raise KeyboardInterrupt()
    monkeypatch.setattr(epic.webpage, "load_url", load_url)

    with pytest.raises(KeyboardInterrupt):
        epic_store.get_latest_metadata(URL)
    assert browser.disconnected == ["driver-1"]


def test_no_browser_gives_no_metadata(epic_store, browser):
    browser.connect_ok = False

    assert epic_store.get_latest_metadata(URL, verbose = True) is None
    assert browser.disconnected == []


def test_an_invalid_metadata_identifier_opens_no_browser(epic_store, browser):
    assert epic_store.get_latest_metadata("") is None
    assert browser.connects == 0
