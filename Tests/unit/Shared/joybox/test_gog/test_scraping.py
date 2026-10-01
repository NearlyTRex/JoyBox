# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import gog


###########################################################
# Store page metadata
#
# The store page is read through a browser; the page is faked here as the
# description element and the detail rows, each holding its text.
###########################################################

class FakePage:

    def __init__(self):
        self.description = None
        self.rows = []
        self.loaded = []
        self.connects = 0
        self.disconnected = []
        self.load_ok = True


@pytest.fixture
def page(gog_store, monkeypatch):
    fake = FakePage()

    def web_connect(**kwargs):
        fake.connects += 1
        return "driver-%d" % fake.connects

    def web_disconnect(web_driver, **kwargs):
        fake.disconnected.append(web_driver)

    def load_url(driver, url):
        fake.loaded.append(url)
        return fake.load_ok

    def wait_for_element(driver, locator, **kwargs):
        if locator.by_value == "description" and fake.description is not None:
            return ("description", fake.description)
        return None

    def get_element(parent, locator, all_elements = False, **kwargs):
        if locator.by_value == "details__row" and all_elements:
            return [("row", text) for text in fake.rows]
        return None

    monkeypatch.setattr(gog_store, "web_connect", web_connect)
    monkeypatch.setattr(gog_store, "web_disconnect", web_disconnect)
    monkeypatch.setattr(gog.webpage, "load_url", load_url)
    monkeypatch.setattr(gog.webpage, "wait_for_element", wait_for_element)
    monkeypatch.setattr(gog.webpage, "get_element", get_element)
    monkeypatch.setattr(gog.webpage, "get_element_children_text", lambda element: element[1])
    monkeypatch.setattr(gog.datautils.time, "sleep", lambda seconds: None)
    return fake


URL = "https://www.gog.com/en/game/the_witcher"


def test_the_description_and_details_are_read(gog_store, page):
    page.description = "A dark fantasy role-playing game."
    page.rows = [
        "Genre: Role-playing - Fantasy",
        "  Company: CD PROJEKT RED / Atari  ",
        "Release date: October 26, 2007",
        "Size: 15 GB",
    ]

    entry = gog_store.get_latest_metadata(URL)

    assert page.loaded == [URL]
    assert entry.get_description() == ["A dark fantasy role-playing game."]
    assert entry.get_genre() == "Role-playing;Fantasy"
    assert entry.get_developer() == "CD PROJEKT RED"
    assert entry.get_publisher() == "Atari"
    assert entry.get_release() == "2007-10-26"


def test_a_single_company_is_the_developer(gog_store, page):
    page.rows = ["Company: Interplay"]

    entry = gog_store.get_latest_metadata(URL)

    assert entry.get_developer() == "Interplay"
    assert entry.get_publisher() is None


def test_companies_past_the_publisher_are_ignored(gog_store, page):
    page.rows = ["Company: Black Isle / Interplay / Bethesda"]

    entry = gog_store.get_latest_metadata(URL)

    assert (entry.get_developer(), entry.get_publisher()) == ("Black Isle", "Interplay")


def test_an_unparsable_release_date_is_left_unset(gog_store, page):
    page.rows = ["Release date: coming soon"]

    entry = gog_store.get_latest_metadata(URL)

    assert entry.get_release() is None
    assert config.metadata_key_release not in entry.game_entry


def test_a_bare_page_gives_an_empty_entry(gog_store, page):
    page.description = ""
    page.rows = ["", "Works on: Windows"]

    entry = gog_store.get_latest_metadata(URL)

    assert entry.get_description() is None
    assert entry.get_developer() is None
    assert entry.get_genre() is None


def test_a_successful_read_disconnects_its_browser_once(gog_store, page):
    gog_store.get_latest_metadata(URL)

    assert page.disconnected == ["driver-1"]


def test_a_page_that_will_not_load_is_retried_then_given_up(gog_store, page):
    page.load_ok = False

    assert gog_store.get_latest_metadata(URL, verbose = True) is None
    assert len(page.loaded) == 3
    assert page.disconnected == ["driver-1", "driver-2", "driver-3"]


def test_an_interrupted_read_still_disconnects_its_browser_once(gog_store, page, monkeypatch):
    def load_url(driver, url):
        raise KeyboardInterrupt()
    monkeypatch.setattr(gog.webpage, "load_url", load_url)

    with pytest.raises(KeyboardInterrupt):
        gog_store.get_latest_metadata(URL)
    assert page.disconnected == ["driver-1"]


def test_no_browser_gives_no_metadata(gog_store, page, monkeypatch):
    monkeypatch.setattr(gog_store, "web_connect", lambda **kwargs: None)

    assert gog_store.get_latest_metadata(URL) is None
    assert page.disconnected == []


def test_an_invalid_identifier_opens_no_browser(gog_store, page):
    assert gog_store.get_latest_metadata("") is None
    assert page.connects == 0


###########################################################
# Assets
###########################################################

@pytest.fixture
def finders(monkeypatch):
    calls = []

    def find_metadata_asset(game_platform, game_name, asset_type, **kwargs):
        calls.append(("asset", game_platform, game_name, asset_type))
        return "cover-%s.jpg" % game_name

    def get_matching_url(url, base_url, starts_with = "", ends_with = "", **kwargs):
        calls.append(("video", url, base_url, starts_with, ends_with))
        return "https://www.youtube.com/embed/abc?enablejsapi=1"

    monkeypatch.setattr(gog.metadataassetcollector, "find_metadata_asset", find_metadata_asset)
    monkeypatch.setattr(gog.webpage, "get_matching_url", get_matching_url)
    return calls


def test_a_box_front_is_searched_by_game_name(gog_store, finders):
    assert gog_store.get_latest_asset_url(URL, config.AssetType.BOXFRONT, game_name = "The Witcher") == "cover-The Witcher.jpg"
    assert finders == [("asset", config.Platform.COMPUTER_GOG, "The Witcher", config.AssetType.BOXFRONT)]


def test_a_box_front_without_a_name_is_searched_by_identifier(gog_store, finders):
    gog_store.get_latest_asset_url(URL, config.AssetType.BOXFRONT)

    assert finders[0][2] == URL


def test_a_video_is_the_embedded_youtube_player(gog_store, finders):
    video = gog_store.get_latest_asset_url(URL, config.AssetType.VIDEO)

    assert video == "https://www.youtube.com/embed/abc?enablejsapi=1"
    assert finders == [("video", URL, "https://www.youtube.com/embed", "https://www.youtube.com/embed", "enablejsapi=1")]


def test_other_asset_types_have_no_url(gog_store, finders):
    assert gog_store.get_latest_asset_url(URL, config.AssetType.LABEL) is None
    assert gog_store.get_latest_asset_url("", config.AssetType.BOXFRONT) is None
    assert finders == []
