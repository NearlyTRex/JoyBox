# Imports
import types

# Third-party imports
import pytest

# Local imports
from joybox.stores import steam


###########################################################
# Store page metadata
#
# The store page is read through a browser; the page is faked here as the
# elements the scraper looks for, keyed by their id.
###########################################################

class FakePage:

    def __init__(self):
        self.elements = {}
        self.texts = {}
        self.keys = []
        self.clicked = []
        self.loaded = []
        self.connects = 0
        self.disconnects = 0
        self.load_ok = True

    def add(self, element_id, text = None):
        self.elements[element_id] = element_id
        if text is not None:
            self.texts[element_id] = text


@pytest.fixture
def page(steam_store, monkeypatch):
    fake = FakePage()

    def web_connect(**kwargs):
        fake.connects += 1
        return "driver"

    def web_disconnect(web_driver, **kwargs):
        fake.disconnects += 1

    def load_url(driver, url):
        fake.loaded.append(url)
        return fake.load_ok

    def find(locator, **kwargs):
        return fake.elements.get(locator.by_value)

    monkeypatch.setattr(steam_store, "web_connect", web_connect)
    monkeypatch.setattr(steam_store, "web_disconnect", web_disconnect)
    monkeypatch.setattr(steam.webpage, "load_url", load_url)
    monkeypatch.setattr(steam.webpage, "wait_for_element", lambda driver, locator, **kwargs: find(locator))
    monkeypatch.setattr(steam.webpage, "get_element", lambda parent, locator, **kwargs: find(locator))
    monkeypatch.setattr(steam.webpage, "get_element_text", lambda element: fake.texts.get(element))
    monkeypatch.setattr(steam.webpage, "get_element_children_text", lambda element: fake.texts.get(element))
    monkeypatch.setattr(steam.webpage, "send_keys_to_element", lambda element, keys: fake.keys.append((element, keys)))
    monkeypatch.setattr(steam.webpage, "click_element", lambda element: fake.clicked.append(element))
    monkeypatch.setattr(steam.datautils.time, "sleep", lambda seconds: None)
    return fake


URL = "https://store.steampowered.com/app/220"


def test_the_description_and_details_are_read(steam_store, page):
    page.add("aboutThisGame", "About This Game A physics shooter.")
    page.add("genresAndManufacturer", "\n".join([
        "Title: Half-Life 2",
        "Genre: Action, Shooter",
        "Developer: Valve",
        "Publisher: Valve",
        "Release Date: Nov 16, 2004",
    ]))

    entry = steam_store.get_latest_metadata(URL)

    assert page.loaded == [URL]
    assert entry.get_description() == ["A physics shooter."]
    assert entry.get_genre() == "Action;Shooter"
    assert entry.get_developer() == "Valve"
    assert entry.get_publisher() == "Valve"
    assert entry.get_release() == "2004-11-16"
    assert page.disconnects >= 1


@pytest.mark.parametrize("heading", ["About This Software", "About This Demo"])
def test_other_description_headings_are_trimmed(steam_store, page, heading):
    page.add("aboutThisGame", heading + " Text.")

    assert steam_store.get_latest_metadata(URL).get_description() == ["Text."]


def test_the_age_gate_is_answered(steam_store, page):
    for element_id in ["app_agegate", "ageDay", "ageMonth", "ageYear", "view_product_page_btn"]:
        page.add(element_id)

    steam_store.get_latest_metadata(URL)

    assert page.keys == [("ageDay", "1"), ("ageMonth", "January"), ("ageYear", "1980")]
    assert page.clicked == ["view_product_page_btn"]


def test_an_age_gate_without_its_selectors_is_left(steam_store, page):
    page.add("app_agegate")

    assert steam_store.get_latest_metadata(URL) is not None
    assert page.keys == []


def test_a_bare_page_gives_an_empty_entry(steam_store, page):
    page.add("aboutThisGame", "")
    page.add("genresAndManufacturer", "")

    entry = steam_store.get_latest_metadata(URL)

    assert entry.get_description() is None
    assert entry.get_developer() is None


def test_an_interrupted_read_still_disconnects_its_browser_once(steam_store, page, monkeypatch):
    def load_url(driver, url):
        raise KeyboardInterrupt()
    monkeypatch.setattr(steam.webpage, "load_url", load_url)

    with pytest.raises(KeyboardInterrupt):
        steam_store.get_latest_metadata(URL)
    assert page.disconnects == 1


def test_a_page_that_will_not_load_is_retried_then_given_up(steam_store, page):
    page.load_ok = False

    assert steam_store.get_latest_metadata(URL) is None
    assert len(page.loaded) == 3
    assert page.connects == 3
    assert page.disconnects == 3


def test_no_browser_gives_no_metadata(steam_store, page, monkeypatch):
    monkeypatch.setattr(steam_store, "web_connect", lambda **kwargs: None)

    assert steam_store.get_latest_metadata(URL) is None


def test_an_invalid_identifier_opens_no_browser(steam_store, page):
    assert steam_store.get_latest_metadata("") is None
    assert page.connects == 0


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

    monkeypatch.setattr(steam.programs, "get_tool_path_config_value", lambda tool, key: "/tools/sgdb")
    monkeypatch.setattr(steam.programs, "get_tool_config_value", lambda tool, key: "steamgrid")
    monkeypatch.setattr(steam.modules, "import_python_module_package",
        lambda module_path, module_name: types.SimpleNamespace(SteamGridDB = SteamGridDB))
    monkeypatch.setattr(steam.image, "get_image_format", lambda url: url.rsplit(".", 1)[-1])
    return state


def add_game(griddb, game_id, name, grids):
    griddb["games"].append(types.SimpleNamespace(id = game_id, name = name, release_date = "2004"))
    griddb["grids"][game_id] = grids


def test_covers_are_found_and_ranked(griddb):
    add_game(griddb, 1, "Half-Life 2", [grid("a.png")])
    add_game(griddb, 2, "Half-Life 2 Episode One", [grid("b.png")])
    add_game(griddb, 3, "Portal", [grid("c.png")])

    results = steam.find_steam_griddb_covers("Half-Life 2")

    assert griddb["key"] == "gridkey"
    assert griddb["searched"] == ["Half-Life+2"]
    assert results[0].get_url() == "a.png"
    assert results[0].get_description() == "Half-Life 2 (2004)"
    assert (results[0].get_width(), results[0].get_height()) == (600, 900)
    assert "c.png" not in [result.get_url() for result in results]


def test_covers_can_be_limited_by_size_and_type(griddb):
    add_game(griddb, 1, "Half-Life 2", [grid("a.png"), grid("b.png", 920, 430), grid("c.jpg")])

    by_size = steam.find_steam_griddb_covers("Half-Life 2", image_dimensions = [920, 430])
    by_type = steam.find_steam_griddb_covers("Half-Life 2", image_types = ["png"])

    assert [result.get_url() for result in by_size] == ["b.png"]
    assert sorted(result.get_url() for result in by_type) == ["a.png", "b.png"]


def test_a_game_without_grids_gives_no_covers(griddb):
    add_game(griddb, 1, "Half-Life 2", None)

    assert steam.find_steam_griddb_covers("Half-Life 2") == []
