# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox import metadatacollector
from joybox import metadataentry


###########################################################
# Fake browser
#
# Pages are dicts from locator value to element (or list of elements), keyed by
# url; a driver sees the page whose url is the longest prefix of its own.
# Elements hold their text, children and link the same way.
###########################################################

class FakeElement:

    def __init__(self, text = None, children_text = None, link = None, children = None, on_click = None):
        self.text = text
        self.children_text = children_text
        self.link = link
        self.children = children or {}
        self.on_click = on_click


class FakeDriver:

    def __init__(self, number):
        self.number = number
        self.url = ""

    def __repr__(self):
        return "driver-%d" % self.number


class FakeBrowser:

    def __init__(self):
        self.pages = {}
        self.drivers = []
        self.created = []
        self.destroyed = []
        self.loaded = []
        self.clicked = []
        self.waits = []
        self.slept = []
        self.failed_creates = 0
        self.failed_loads = 0
        self.unloadable = set()

    def page_for(self, url):
        matches = [key for key in self.pages if url.startswith(key)]
        if not matches:
            return {}
        return self.pages[max(matches, key = len)]

    def lookup(self, parent, by_value):
        if isinstance(parent, FakeDriver):
            return self.page_for(parent.url).get(by_value)
        return parent.children.get(by_value)

    def destroyed_drivers(self):
        return [driver for driver, kwargs in self.destroyed]


@pytest.fixture
def browser(monkeypatch):
    fake = FakeBrowser()
    webpage = metadatacollector.webpage

    def create_web_driver(**kwargs):
        fake.created.append(kwargs)
        if fake.failed_creates:
            fake.failed_creates -= 1
            return None
        driver = FakeDriver(len(fake.drivers) + 1)
        fake.drivers.append(driver)
        return driver

    def destroy_web_driver(driver, **kwargs):
        fake.destroyed.append((driver, kwargs))
        return True

    def load_url(driver, url):
        fake.loaded.append(url)
        if fake.failed_loads:
            fake.failed_loads -= 1
            return False
        if url in fake.unloadable:
            return False
        driver.url = url
        return True

    def wait_for_element(driver, locator, wait_time = 15, **kwargs):
        fake.waits.append(wait_time)
        return fake.lookup(driver, locator.by_value)

    def get_element(parent, locator, all_elements = False, **kwargs):
        found = fake.lookup(parent, locator.by_value)
        assert found is None or isinstance(found, list) == all_elements
        return found

    def click_element(element, **kwargs):
        fake.clicked.append(element)
        if element.link:
            fake.drivers[-1].url = element.link
        if element.on_click:
            element.on_click()
        return True

    def is_url_loaded(driver, url, verbose = False):
        return driver.url.startswith(url)

    monkeypatch.setattr(webpage, "create_web_driver", create_web_driver)
    monkeypatch.setattr(webpage, "destroy_web_driver", destroy_web_driver)
    monkeypatch.setattr(webpage, "load_url", load_url)
    monkeypatch.setattr(webpage, "wait_for_element", wait_for_element)
    monkeypatch.setattr(webpage, "get_element", get_element)
    monkeypatch.setattr(webpage, "click_element", click_element)
    monkeypatch.setattr(webpage, "is_url_loaded", is_url_loaded)
    monkeypatch.setattr(webpage, "get_element_text", lambda element, verbose = False: element.text if element else None)
    monkeypatch.setattr(webpage, "get_element_children_text", lambda element, verbose = False: element.children_text)
    monkeypatch.setattr(webpage, "get_element_link_url", lambda element, verbose = False: element.link)
    monkeypatch.setattr(metadatacollector.datautils.time, "sleep", fake.slept.append)
    return fake


PLATFORM = config.Platform.NINTENDO_64
PLATFORM_NAME = config.gamefaqs_platforms[PLATFORM][0]
GAME_NAME = "Super Mario 64 (USA)"


###########################################################
# TheGamesDB
###########################################################

TGDB_SEARCH_URL = "https://thegamesdb.net/search.php?name=Super+Mario+64"
TGDB_GAME_URL = "https://thegamesdb.net/game.php?id=1"
TGDB_OTHER_URL = "https://thegamesdb.net/game.php?id=2"


def tgdb_results(browser, *cells):
    browser.pages[TGDB_SEARCH_URL] = {
        "container-fluid": FakeElement(children = {"card-footer": list(cells)})}


def tgdb_game(browser, description = None, paragraphs = (), url = TGDB_GAME_URL):
    page = {"card-body": [FakeElement(children = {"p": [FakeElement(text = text) for text in paragraphs]})]}
    if description is not None:
        page["game-overview"] = FakeElement(text = description)
    browser.pages[url] = page


def tgdb_ready(browser):
    tgdb_results(browser, FakeElement(text = "Super Mario 64\nNintendo 64", link = TGDB_GAME_URL))
    tgdb_game(browser, description = "A plumber collects stars.")


def test_tgdb_reads_the_description_and_details_of_the_best_match(browser):
    tgdb_ready(browser)
    tgdb_game(browser, description = "A plumber collects stars.", paragraphs = [
        "Genre(s): Platformer | Action",
        "Co-op: No",
        "Developer(s): Nintendo EAD",
        "Publishers(s): Nintendo",
        "Players: 1",
        "ReleaseDate: 1996-06-23",
    ])

    entry = metadatacollector.collect_metadata_from_tgdb(PLATFORM, GAME_NAME)

    assert browser.loaded == [TGDB_SEARCH_URL]
    assert browser.waits == [15, 15]
    assert entry.get_description() == ["A plumber collects stars."]
    assert entry.get_genre() == "Platformer;Action"
    assert entry.get_coop() == "No"
    assert entry.get_developer() == "Nintendo EAD"
    assert entry.get_publisher() == "Nintendo"
    assert entry.get_players() == "1"
    assert entry.get_release() == "1996-06-23"


def test_tgdb_opens_the_result_whose_first_line_is_closest_to_the_name(browser):
    best = FakeElement(text = "Super Mario 64\nNintendo 64", link = TGDB_GAME_URL)
    tgdb_results(browser,
        FakeElement(text = "Super Mario 64 DS\nNintendo DS", link = TGDB_OTHER_URL),
        best,
        FakeElement(text = "Mario Kart 64", link = TGDB_OTHER_URL))
    tgdb_game(browser, paragraphs = ["Developer(s): Nintendo EAD"])
    tgdb_game(browser, paragraphs = ["Developer(s): Someone Else"], url = TGDB_OTHER_URL)

    entry = metadatacollector.collect_metadata_from_tgdb(PLATFORM, GAME_NAME)

    assert browser.clicked == [best]
    assert entry.get_developer() == "Nintendo EAD"


def test_tgdb_results_without_a_title_are_not_candidates(browser):
    titled = FakeElement(text = "Mario Kart 64", link = TGDB_GAME_URL)
    tgdb_results(browser, FakeElement(text = None), FakeElement(text = ""), FakeElement(text = "\nNintendo 64"), titled)
    tgdb_game(browser)

    metadatacollector.collect_metadata_from_tgdb(PLATFORM, GAME_NAME)

    assert browser.clicked == [titled]


@pytest.mark.parametrize("cells", [[], [FakeElement(text = None)]])
def test_tgdb_without_a_titled_result_gives_no_metadata_and_does_not_retry(browser, cells):
    tgdb_results(browser, *cells)
    browser.pages[TGDB_SEARCH_URL]["card-body"] = [FakeElement(children = {"p": [FakeElement(text = "Players: 4")]})]

    assert metadatacollector.collect_metadata_from_tgdb(PLATFORM, GAME_NAME) is None
    assert len(browser.drivers) == 1
    assert browser.slept == []


def test_tgdb_without_a_results_container_gives_no_metadata(browser):
    assert metadatacollector.collect_metadata_from_tgdb(PLATFORM, GAME_NAME) is None
    assert len(browser.drivers) == 1
    assert browser.clicked == []


def test_tgdb_gives_no_metadata_when_the_click_stays_on_the_search_page(browser):
    tgdb_results(browser, FakeElement(text = "Super Mario 64"))

    assert metadatacollector.collect_metadata_from_tgdb(PLATFORM, GAME_NAME) is None
    assert len(browser.clicked) == 1


def test_tgdb_skips_empty_unknown_and_unparsable_details(browser):
    tgdb_ready(browser)
    tgdb_game(browser, description = "   ", paragraphs = [
        None,
        "",
        "Genre(s):   ",
        "Platform: Nintendo 64",
        "ReleaseDate: TBA",
        "  Developer(s): Nintendo EAD  ",
    ])

    entry = metadatacollector.collect_metadata_from_tgdb(PLATFORM, GAME_NAME)

    assert entry.game_entry == {config.metadata_key_developer: "Nintendo EAD"}


def test_tgdb_game_page_without_details_gives_an_empty_entry(browser):
    tgdb_ready(browser)
    browser.pages[TGDB_GAME_URL] = {"card-body": [FakeElement()]}

    entry = metadatacollector.collect_metadata_from_tgdb(PLATFORM, GAME_NAME)

    assert isinstance(entry, metadataentry.MetadataEntry)
    assert entry.game_entry == {}


def test_tgdb_game_page_with_nothing_on_it_gives_an_empty_entry(browser):
    tgdb_ready(browser)
    browser.pages[TGDB_GAME_URL] = {}

    assert metadatacollector.collect_metadata_from_tgdb(PLATFORM, GAME_NAME).game_entry == {}


###########################################################
# GameFAQs
###########################################################

GAMEFAQS_HOME_URL = "https://gamefaqs.gamespot.com"
GAMEFAQS_SEARCH_URL = "https://gamefaqs.gamespot.com/search_advanced?game=Super+Mario+64"
GAMEFAQS_GAME_URL = "https://gamefaqs.gamespot.com/n64/198848-super-mario-64"
GAMEFAQS_OTHER_URL = "https://gamefaqs.gamespot.com/ds/920785-super-mario-64-ds"


def gamefaqs_row(platform = PLATFORM_NAME, name = "Super Mario 64", link = GAMEFAQS_GAME_URL, columns = 4):
    cells = [
        FakeElement(children_text = platform),
        FakeElement(children_text = name, link = link),
    ] + [FakeElement() for _ in range(columns - 2)]
    return FakeElement(children = {"td": cells[:columns]})


def gamefaqs_results(browser, *rows):
    table = FakeElement(children = {"tr": list(rows)})
    browser.pages[GAMEFAQS_SEARCH_URL] = {"span12": FakeElement(children = {"tbody": table})}


def gamefaqs_game(browser, description = None, details = (), url = GAMEFAQS_GAME_URL):
    page = {"content": [FakeElement(text = text) for text in details]}
    if description is not None:
        page["game_desc"] = FakeElement(text = description)
    browser.pages[url] = page
    return page


def gamefaqs_ready(browser):
    browser.pages[GAMEFAQS_HOME_URL] = {"home_jbi_ft": FakeElement()}
    gamefaqs_results(browser, gamefaqs_row())
    gamefaqs_game(browser, description = "A plumber collects stars.")


def test_gamefaqs_reads_the_description_and_details_of_the_platform_match(browser):
    gamefaqs_ready(browser)
    gamefaqs_game(browser, description = "A plumber collects stars.", details = [
        "Genre: Action » Platformer » 3D",
        "Developer: Nintendo EAD",
        "Publisher: Nintendo",
        "First Released: Jun 23, 1996",
    ])

    entry = metadatacollector.collect_metadata_from_gamefaqs(PLATFORM, GAME_NAME)

    assert browser.loaded == [GAMEFAQS_HOME_URL, GAMEFAQS_SEARCH_URL, GAMEFAQS_GAME_URL]
    assert entry.get_description() == ["A plumber collects stars."]
    assert entry.get_genre() == "Action;Platformer;3D"
    assert entry.get_developer() == "Nintendo EAD"
    assert entry.get_publisher() == "Nintendo"
    assert entry.get_release() == "1996-06-23"


def test_gamefaqs_a_combined_developer_publisher_sets_both(browser):
    gamefaqs_ready(browser)
    gamefaqs_game(browser, details = ["Developer/Publisher: Nintendo", "Release: 9/29/1996"])

    entry = metadatacollector.collect_metadata_from_gamefaqs(PLATFORM, GAME_NAME)

    assert (entry.get_developer(), entry.get_publisher()) == ("Nintendo", "Nintendo")
    assert entry.get_release() == "1996-09-29"


def test_gamefaqs_skips_empty_unknown_and_unparsable_details(browser):
    gamefaqs_ready(browser)
    gamefaqs_game(browser, description = "", details = [
        None,
        "Genre:",
        "Rating: E",
        "Release: TBA",
        "  Publisher: Nintendo  ",
    ])

    entry = metadatacollector.collect_metadata_from_gamefaqs(PLATFORM, GAME_NAME)

    assert entry.game_entry == {config.metadata_key_publisher: "Nintendo"}


def test_gamefaqs_expands_a_truncated_description(browser):
    gamefaqs_ready(browser)
    page = gamefaqs_game(browser, description = "A plumber... more »")
    description = page["game_desc"]
    more = FakeElement(on_click = lambda: setattr(description, "text", "A plumber collects stars."))
    page["more »"] = more

    entry = metadatacollector.collect_metadata_from_gamefaqs(PLATFORM, GAME_NAME)

    assert browser.clicked == [more]
    assert entry.get_description() == ["A plumber collects stars."]


def test_gamefaqs_keeps_a_truncated_description_without_a_more_link(browser):
    gamefaqs_ready(browser)
    gamefaqs_game(browser, description = "A plumber more »")

    entry = metadatacollector.collect_metadata_from_gamefaqs(PLATFORM, GAME_NAME)

    assert browser.clicked == []
    assert entry.get_description() == ["A plumber more >>"]


def test_gamefaqs_opens_the_first_usable_result_on_the_platform(browser):
    gamefaqs_ready(browser)
    gamefaqs_results(browser,
        gamefaqs_row(platform = "DS", link = GAMEFAQS_OTHER_URL),
        gamefaqs_row(columns = 3),
        FakeElement(),
        gamefaqs_row(platform = None),
        gamefaqs_row(name = ""),
        gamefaqs_row(link = None),
        gamefaqs_row(link = GAMEFAQS_OTHER_URL + "/unloadable"),
        gamefaqs_row(platform = " %s " % PLATFORM_NAME),
        gamefaqs_row(link = GAMEFAQS_OTHER_URL))
    browser.unloadable.add(GAMEFAQS_OTHER_URL + "/unloadable")

    metadatacollector.collect_metadata_from_gamefaqs(PLATFORM, GAME_NAME)

    assert browser.loaded[2:] == [GAMEFAQS_OTHER_URL + "/unloadable", GAMEFAQS_GAME_URL]


@pytest.mark.parametrize("rows", [[], [gamefaqs_row(platform = "DS")]])
def test_gamefaqs_without_a_platform_match_gives_no_metadata_and_does_not_retry(browser, rows):
    gamefaqs_ready(browser)
    gamefaqs_results(browser, *rows)
    browser.pages[GAMEFAQS_SEARCH_URL]["content"] = [FakeElement(text = "Genre: Search")]

    assert metadatacollector.collect_metadata_from_gamefaqs(PLATFORM, GAME_NAME) is None
    assert len(browser.drivers) == 1
    assert browser.slept == []


def test_gamefaqs_without_a_results_table_gives_no_metadata(browser):
    gamefaqs_ready(browser)
    browser.pages[GAMEFAQS_SEARCH_URL] = {"span12": FakeElement()}

    assert metadatacollector.collect_metadata_from_gamefaqs(PLATFORM, GAME_NAME) is None


def test_gamefaqs_without_a_results_container_gives_no_metadata(browser):
    gamefaqs_ready(browser)
    del browser.pages[GAMEFAQS_SEARCH_URL]

    assert metadatacollector.collect_metadata_from_gamefaqs(PLATFORM, GAME_NAME) is None
    assert len(browser.drivers) == 1


def test_gamefaqs_without_the_homepage_marker_is_retried_then_given_up(browser):
    gamefaqs_ready(browser)
    del browser.pages[GAMEFAQS_HOME_URL]

    assert metadatacollector.collect_metadata_from_gamefaqs(PLATFORM, GAME_NAME) is None
    assert browser.loaded == [GAMEFAQS_HOME_URL] * 3
    assert browser.destroyed_drivers() == browser.drivers


def test_gamefaqs_a_search_page_that_will_not_load_is_retried(browser):
    gamefaqs_ready(browser)
    browser.unloadable.add(GAMEFAQS_SEARCH_URL)

    assert metadatacollector.collect_metadata_from_gamefaqs(PLATFORM, GAME_NAME) is None
    assert browser.loaded == [GAMEFAQS_HOME_URL, GAMEFAQS_SEARCH_URL] * 3


def test_gamefaqs_a_platform_it_does_not_list_opens_no_browser(browser):
    assert metadatacollector.collect_metadata_from_gamefaqs("Not A Platform", GAME_NAME) is None
    assert browser.created == []


###########################################################
# BigFishGames
###########################################################

BIGFISH_SEARCH_URL = "https://www.bigfishgames.com/us/en/games/search.html?platform=150&language=114&search_query=Mystery+Case+Files"


def bigfish_page(browser, description = "Find the clues.", bullets = None):
    page = {}
    if description is not None:
        page["productFullDetail__descriptionContent"] = FakeElement(text = description)
    if bullets is not None:
        page["productFullDetail__bullets"] = FakeElement(text = bullets)
    browser.pages[BIGFISH_SEARCH_URL] = page


def bigfish_ready(browser):
    bigfish_page(browser)


def test_bigfish_joins_the_description_and_bullets(browser):
    bigfish_page(browser, description = "  Find the clues.  ", bullets = "  Twenty levels  ")

    entry = metadatacollector.collect_metadata_from_bigfishgames(config.Platform.COMPUTER_LEGACY_GAMES, "Mystery Case Files")

    assert browser.loaded == [BIGFISH_SEARCH_URL]
    assert entry.get_description() == ["Find the clues.", ".", "Twenty levels"]


@pytest.mark.parametrize("bullets", [None, "   "])
def test_bigfish_without_bullets_uses_the_description_alone(browser, bullets):
    bigfish_page(browser, bullets = bullets)

    entry = metadatacollector.collect_metadata_from_bigfishgames(config.Platform.COMPUTER_LEGACY_GAMES, "Mystery Case Files")

    assert entry.get_description() == ["Find the clues."]


def test_bigfish_a_blank_page_gives_an_empty_entry(browser):
    bigfish_page(browser, description = "   ", bullets = "")

    entry = metadatacollector.collect_metadata_from_bigfishgames(config.Platform.COMPUTER_LEGACY_GAMES, "Mystery Case Files")

    assert entry.game_entry == {}


def test_bigfish_without_a_description_gives_no_metadata_and_does_not_retry(browser):
    bigfish_page(browser, description = None, bullets = "Twenty levels")

    assert metadatacollector.collect_metadata_from_bigfishgames(config.Platform.COMPUTER_LEGACY_GAMES, "Mystery Case Files") is None
    assert len(browser.drivers) == 1
    assert browser.slept == []


###########################################################
# Browser lifecycle
#
# Every collector opens a fresh browser per attempt and must close each one it
# opened exactly once, whatever happens.
###########################################################

COLLECTORS = [
    pytest.param(metadatacollector.collect_metadata_from_tgdb, tgdb_ready, PLATFORM, GAME_NAME, id = "tgdb"),
    pytest.param(metadatacollector.collect_metadata_from_gamefaqs, gamefaqs_ready, PLATFORM, GAME_NAME, id = "gamefaqs"),
    pytest.param(metadatacollector.collect_metadata_from_bigfishgames, bigfish_ready,
        config.Platform.COMPUTER_LEGACY_GAMES, "Mystery Case Files", id = "bigfish"),
]


@pytest.mark.parametrize("collect, ready, platform, name", COLLECTORS)
def test_a_successful_collection_closes_its_browser_once(browser, collect, ready, platform, name):
    ready(browser)

    entry = collect(platform, name)

    assert entry.get_description()
    assert browser.drivers == [browser.drivers[0]]
    assert browser.destroyed_drivers() == browser.drivers
    assert browser.slept == []


@pytest.mark.parametrize("collect, ready, platform, name", COLLECTORS)
def test_every_browser_is_closed_once_when_all_attempts_fail(browser, collect, ready, platform, name):
    ready(browser)
    browser.failed_loads = 99

    assert collect(platform, name, verbose = True) is None
    assert len(browser.drivers) == 3
    assert browser.destroyed_drivers() == browser.drivers
    assert browser.slept == [2, 4]


@pytest.mark.parametrize("collect, ready, platform, name", COLLECTORS)
def test_a_failure_then_success_closes_both_browsers_once(browser, collect, ready, platform, name):
    ready(browser)
    browser.failed_loads = 1

    assert collect(platform, name).get_description()
    assert len(browser.drivers) == 2
    assert browser.destroyed_drivers() == browser.drivers
    assert browser.slept == [2]


@pytest.mark.parametrize("collect, ready, platform, name", COLLECTORS)
def test_an_interrupted_collection_still_closes_its_browser_once(browser, collect, ready, platform, name, monkeypatch):
    ready(browser)

    def interrupt(driver, url):
        raise KeyboardInterrupt()
    monkeypatch.setattr(metadatacollector.webpage, "load_url", interrupt)

    with pytest.raises(KeyboardInterrupt):
        collect(platform, name)
    assert browser.destroyed_drivers() == browser.drivers == [browser.drivers[0]]


@pytest.mark.parametrize("collect, ready, platform, name", COLLECTORS)
def test_no_browser_is_retried_then_gives_no_metadata(browser, collect, ready, platform, name):
    ready(browser)
    browser.failed_creates = 3

    assert collect(platform, name) is None
    assert len(browser.created) == 3
    assert browser.destroyed == []


@pytest.mark.parametrize("collect, ready, platform, name", COLLECTORS)
def test_a_browser_that_starts_on_retry_is_used_and_closed(browser, collect, ready, platform, name):
    ready(browser)
    browser.failed_creates = 1

    assert collect(platform, name).get_description()
    assert len(browser.drivers) == 1
    assert browser.destroyed_drivers() == browser.drivers


@pytest.mark.parametrize("collect, ready, platform, name", COLLECTORS)
def test_an_empty_result_after_a_failure_is_retried(browser, collect, ready, platform, name):
    browser.failed_loads = 1

    assert collect(platform, name) is None
    assert len(browser.drivers) == 3
    assert browser.destroyed_drivers() == browser.drivers


@pytest.mark.parametrize("collect, ready, platform, name", COLLECTORS)
def test_the_browser_follows_the_callers_run_flags(browser, collect, ready, platform, name):
    ready(browser)

    collect(platform, name, verbose = True, pretend_run = True)

    assert browser.created == [{"make_headless": True, "verbose": True, "pretend_run": True, "exit_on_failure": False}]
    assert browser.destroyed[0][1] == {"verbose": True, "pretend_run": True, "exit_on_failure": False}


@pytest.mark.parametrize("collect, ready, platform, name", COLLECTORS)
def test_a_pretend_run_without_a_browser_does_not_retry(browser, collect, ready, platform, name):
    browser.failed_creates = 3

    assert collect(platform, name, pretend_run = True) is None
    assert len(browser.created) == 1
    assert browser.slept == []


###########################################################
# All sources
###########################################################

def test_all_sources_gives_the_gamefaqs_metadata(monkeypatch):
    calls = []

    def collect_metadata_from_gamefaqs(**kwargs):
        calls.append(kwargs)
        entry = metadataentry.MetadataEntry()
        entry.set_developer("Nintendo EAD")
        return entry
    monkeypatch.setattr(metadatacollector, "collect_metadata_from_gamefaqs", collect_metadata_from_gamefaqs)

    entry = metadatacollector.collect_metadata_from_all(PLATFORM, GAME_NAME, config.metadata_keys_downloadable,
        verbose = True, pretend_run = True, exit_on_failure = True)

    assert entry.game_entry == {config.metadata_key_developer: "Nintendo EAD"}
    assert calls == [{"game_platform": PLATFORM, "game_name": GAME_NAME,
        "verbose": True, "pretend_run": True, "exit_on_failure": True}]


def test_all_sources_without_gamefaqs_metadata_gives_an_empty_entry(monkeypatch):
    monkeypatch.setattr(metadatacollector, "collect_metadata_from_gamefaqs", lambda **kwargs: None)

    entry = metadatacollector.collect_metadata_from_all(PLATFORM, GAME_NAME, config.metadata_keys_downloadable)

    assert isinstance(entry, metadataentry.MetadataEntry)
    assert entry.game_entry == {}
