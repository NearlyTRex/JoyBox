# Third-party imports
import pytest

# Local imports
from joybox import webpage
from webpage_helpers import FakeDriver, FakeElement, FakeParent, ClickableElement

pytest.importorskip("bs4")
By = pytest.importorskip("selenium.webdriver.common.by").By
exceptions = pytest.importorskip("selenium.common.exceptions")


###########################################################
# Finding elements
#
# A scrape looks up elements against a live browser. Every lookup here has to
# come back with None rather than raising, because a store page that changed
# its markup is an ordinary outcome, not a crash.
###########################################################

LOCATOR = webpage.ElementLocator({"css_selector": "div.game"})


def test_an_element_is_looked_up_by_its_locator():
    found = FakeElement(text = "Chrono Trigger")
    parent = FakeParent(found = found)

    assert webpage.get_element(parent, LOCATOR) is found
    assert parent.lookups == [(By.CSS_SELECTOR, "div.game")]


def test_every_match_can_be_asked_for():
    found = [FakeElement(text = "one"), FakeElement(text = "two")]
    parent = FakeParent(found = found)

    assert webpage.get_element(parent, LOCATOR, all_elements = True) == found


def test_an_element_that_is_not_there_is_absent():
    parent = FakeParent(error = exceptions.NoSuchElementException("gone"))

    assert webpage.get_element(parent, LOCATOR) is None


def test_a_browser_error_during_a_lookup_is_absent():
    parent = FakeParent(error = exceptions.WebDriverException("disconnected"))

    assert webpage.get_element(parent, LOCATOR) is None


def test_a_dead_session_looks_nothing_up():
    driver = FakeDriver(dead = True)

    assert webpage.get_element(driver, LOCATOR) is None


def test_an_unexpected_lookup_error_can_quit_the_program():
    parent = FakeParent(error = ValueError("something else"))

    with pytest.raises(SystemExit):
        webpage.get_element(parent, LOCATOR, exit_on_failure = True)


###########################################################
# Waiting for elements
###########################################################

@pytest.fixture
def waits(monkeypatch):
    # Replaces selenium's wait so the timeout is never actually spent.
    import selenium.webdriver.support.ui as ui

    state = {"result": FakeElement(text = "ready"), "error": None, "timeouts": []}

    class FakeWait:
        def __init__(self, driver, timeout):
            state["timeouts"].append(timeout)

        def until(self, condition):
            if state["error"]:
                raise state["error"]
            return state["result"]

    monkeypatch.setattr(ui, "WebDriverWait", FakeWait)
    return state


def test_a_wait_returns_the_element_it_found(waits):
    assert webpage.wait_for_element(FakeDriver(), LOCATOR) is waits["result"]


def test_a_wait_uses_the_timeout_it_was_given(waits):
    webpage.wait_for_element(FakeDriver(), LOCATOR, wait_time = 30)

    assert waits["timeouts"] == [30]


def test_a_wait_that_times_out_finds_nothing(waits):
    waits["error"] = exceptions.TimeoutException("timed out")

    assert webpage.wait_for_element(FakeDriver(), LOCATOR) is None


def test_a_wait_against_a_dead_session_finds_nothing(waits):
    # The wait would otherwise sit out its whole timeout against a browser
    # that is already gone.
    assert webpage.wait_for_element(FakeDriver(dead = True), LOCATOR) is None
    assert waits["timeouts"] == []


def test_a_browser_error_during_a_wait_finds_nothing(waits):
    waits["error"] = exceptions.WebDriverException("disconnected")

    assert webpage.wait_for_element(FakeDriver(), LOCATOR) is None


def test_waiting_for_all_elements_returns_the_result(waits):
    assert webpage.wait_for_all_elements(FakeDriver(), [LOCATOR]) is waits["result"]


def test_waiting_for_any_element_returns_the_result(waits):
    assert webpage.wait_for_any_element(FakeDriver(), [LOCATOR]) is waits["result"]


@pytest.mark.parametrize("waiter", [
    webpage.wait_for_all_elements,
    webpage.wait_for_any_element,
])
def test_a_group_wait_that_fails_finds_nothing(waits, waiter):
    waits["error"] = exceptions.TimeoutException("timed out")

    assert waiter(FakeDriver(), [LOCATOR]) is None


@pytest.mark.parametrize("waiter", [
    webpage.wait_for_all_elements,
    webpage.wait_for_any_element,
])
def test_a_failed_group_wait_can_quit_the_program(waits, waiter):
    waits["error"] = exceptions.TimeoutException("timed out")

    with pytest.raises(SystemExit):
        waiter(FakeDriver(), [LOCATOR], exit_on_failure = True)


###########################################################
# Acting on elements
###########################################################

def test_an_element_is_clicked():
    element = ClickableElement()

    assert webpage.click_element(element) is True
    assert element.clicks == 1


def test_nothing_is_clicked_when_there_is_no_element():
    assert webpage.click_element(None) is False


def test_pretending_clicks_nothing():
    element = ClickableElement()

    assert webpage.click_element(element, pretend_run = True) is True
    assert element.clicks == 0


def test_an_element_that_will_not_be_clicked_reports_failure():
    element = ClickableElement(error = exceptions.ElementNotInteractableException("covered"))

    assert webpage.click_element(element) is False


def test_a_failed_click_can_quit_the_program():
    element = ClickableElement(error = exceptions.WebDriverException("gone"))

    with pytest.raises(SystemExit):
        webpage.click_element(element, exit_on_failure = True)


def test_keys_are_sent_to_an_element():
    element = ClickableElement()

    assert webpage.send_keys_to_element(element, "password") is True
    assert element.keys == ["password"]


def test_no_keys_are_sent_without_an_element():
    assert webpage.send_keys_to_element(None, "text") is False


def test_nothing_is_sent_when_there_are_no_keys():
    # An empty field is different from a field nobody meant to fill.
    element = ClickableElement()

    assert webpage.send_keys_to_element(element, None) is False
    assert element.keys == []


def test_pretending_sends_no_keys():
    element = ClickableElement()

    assert webpage.send_keys_to_element(element, "text", pretend_run = True) is True
    assert element.keys == []


def test_keys_that_cannot_be_sent_report_failure():
    element = ClickableElement(error = exceptions.WebDriverException("detached"))

    assert webpage.send_keys_to_element(element, "text") is False


def test_failing_to_send_keys_can_quit_the_program():
    element = ClickableElement(error = exceptions.WebDriverException("detached"))

    with pytest.raises(SystemExit):
        webpage.send_keys_to_element(element, "text", exit_on_failure = True)


###########################################################
# Page source
###########################################################

def test_the_page_source_is_read():
    driver = FakeDriver()

    assert webpage.get_page_source(driver) == "<html><body>page</body></html>"


def test_a_url_is_loaded_before_its_source_is_read():
    driver = FakeDriver()

    webpage.get_page_source(driver, url = "https://store.example/game")

    assert driver.visited == ["https://store.example/game"]


def test_no_source_is_read_when_the_url_will_not_load():
    driver = FakeDriver(dead = True)

    assert webpage.get_page_source(driver, url = "https://store.example/game") is None


@pytest.mark.parametrize("url", [123, ["https://store.example"], {"url": "x"}])
def test_a_url_that_is_not_a_string_is_refused(url):
    assert webpage.get_page_source(FakeDriver(), url = url) is None


def test_a_dead_session_has_no_page_source():
    assert webpage.get_page_source(FakeDriver(dead = True)) is None


def test_pretending_reads_no_source():
    assert webpage.get_page_source(FakeDriver(), pretend_run = True) == ""


###########################################################
# Fetching a page
#
# The driver is tried first because store pages render their content with
# javascript, and requests is the fallback for everything simpler.
###########################################################

@pytest.fixture
def fetches(monkeypatch):
    import sys
    import types

    state = {"driver": FakeDriver(), "source": "<html>driver</html>",
             "text": "<html>requests</html>", "error": None, "destroyed": []}

    monkeypatch.setattr(webpage, "create_web_driver", lambda **kwargs: state["driver"])
    monkeypatch.setattr(
        webpage, "get_page_source", lambda **kwargs: state["source"])
    monkeypatch.setattr(
        webpage, "destroy_web_driver",
        lambda driver, **kwargs: state["destroyed"].append(driver))

    def get(url, params = None):
        if state["error"]:
            raise state["error"]
        return types.SimpleNamespace(text = state["text"])

    module = types.ModuleType("requests")
    module.get = get
    monkeypatch.setitem(sys.modules, "requests", module)
    return state


def test_a_page_is_fetched_with_the_driver(fetches):
    assert webpage.get_website_text("https://store.example") == "<html>driver</html>"


def test_the_driver_is_shut_down_after_a_fetch(fetches):
    # A driver left running holds a browser process open for the whole run.
    webpage.get_website_text("https://store.example")

    assert fetches["destroyed"] == [fetches["driver"]]


def test_a_page_falls_back_to_a_plain_request(fetches):
    fetches["driver"] = None

    assert webpage.get_website_text("https://store.example") == "<html>requests</html>"


def test_an_empty_driver_result_falls_back_to_a_plain_request(fetches):
    fetches["source"] = ""

    assert webpage.get_website_text("https://store.example") == "<html>requests</html>"


def test_a_page_nothing_can_fetch_is_empty(fetches):
    fetches["driver"] = None
    fetches["error"] = OSError("no route to host")

    assert webpage.get_website_text("https://store.example") == ""


###########################################################
# Matching urls on a page
###########################################################

@pytest.fixture
def page(monkeypatch):
    state = {"html": ""}
    monkeypatch.setattr(webpage, "get_website_text", lambda **kwargs: state["html"])
    return state


def matching(page, html, **kwargs):
    page["html"] = html
    return webpage.get_matching_urls(
        url = "https://releases.example/list",
        base_url = "https://releases.example",
        **kwargs)


def test_an_absolute_link_is_found(page):
    found = matching(page, '<a href="https://cdn.example/app-1.0.zip">download</a>')

    assert "https://cdn.example/app-1.0.zip" in found


def test_a_relative_link_is_resolved_against_the_base(page):
    # A relative href is useless to the downloader on its own.
    found = matching(page, '<a href="/files/app-1.0.zip">download</a>')

    assert "https://releases.example/files/app-1.0.zip" in found


def test_a_protocol_relative_iframe_is_given_a_scheme(page):
    found = matching(
        page, '<iframe src="//cdn.example/app-1.0.zip"></iframe>',
        starts_with = "https://cdn")

    assert "https://cdn.example/app-1.0.zip" in found


def test_a_link_in_an_attribute_is_found(page):
    found = matching(
        page, '<div data-download="https://cdn.example/app-1.0.zip"></div>',
        starts_with = "https://cdn")

    assert "https://cdn.example/app-1.0.zip" in found


def test_a_link_written_as_text_is_found(page):
    found = matching(
        page, "<p>https://cdn.example/app-1.0.zip</p>",
        starts_with = "https://cdn")

    assert "https://cdn.example/app-1.0.zip" in found


def test_a_query_string_is_offered_stripped_as_well(page):
    # Release links often carry a signed query that is not part of the name.
    found = matching(
        page, '<a href="https://cdn.example/app-1.0.zip?token=abc">download</a>',
        starts_with = "https://cdn")

    assert "https://cdn.example/app-1.0.zip" in found


def test_only_links_with_the_wanted_ending_are_returned(page):
    found = matching(page, """
        <a href="https://cdn.example/app-1.0.zip">zip</a>
        <a href="https://cdn.example/app-1.0.txt">notes</a>
    """, starts_with = "https://cdn", ends_with = r"\.zip")

    assert found == ["https://cdn.example/app-1.0.zip"]


def test_only_links_with_the_wanted_start_are_returned(page):
    found = matching(page, """
        <a href="https://cdn.example/app.zip">ours</a>
        <a href="https://other.example/app.zip">theirs</a>
    """, starts_with = "https://cdn", ends_with = r"\.zip")

    assert found == ["https://cdn.example/app.zip"]


def test_the_same_link_is_only_returned_once(page):
    # The same href is picked up as a link, as an attribute and as text.
    found = matching(page, """
        <a href="https://cdn.example/app.zip">one</a>
        <a href="https://cdn.example/app.zip">again</a>
    """, starts_with = "https://cdn")

    assert found == ["https://cdn.example/app.zip"]


def test_a_page_with_no_links_matches_nothing(page):
    assert matching(page, "<html><body>nothing here</body></html>") == []


def test_a_page_that_could_not_be_fetched_matches_nothing(page):
    assert matching(page, "") == []


###########################################################
# Picking one url
###########################################################

def test_the_first_match_is_taken_by_default(page):
    page["html"] = """
        <a href="https://cdn.example/app-1.0.zip">old</a>
        <a href="https://cdn.example/app-2.0.zip">new</a>
    """

    found = webpage.get_matching_url(
        url = "https://releases.example/list",
        base_url = "https://releases.example",
        starts_with = "https://cdn",
        ends_with = r"\.zip")

    assert found == "https://cdn.example/app-1.0.zip"


def test_the_latest_release_can_be_asked_for(page):
    # Release pages list oldest first as often as not, so "latest" is decided
    # by the filename rather than by position.
    page["html"] = """
        <a href="https://cdn.example/app-1.0.zip">old</a>
        <a href="https://cdn.example/app-3.0.zip">newest</a>
        <a href="https://cdn.example/app-2.0.zip">middle</a>
    """

    found = webpage.get_matching_url(
        url = "https://releases.example/list",
        base_url = "https://releases.example",
        starts_with = "https://cdn",
        ends_with = r"\.zip",
        get_latest = True)

    assert found == "https://cdn.example/app-3.0.zip"


def test_nothing_matching_yields_nothing(page):
    page["html"] = '<a href="https://cdn.example/app.txt">notes</a>'

    assert webpage.get_matching_url(
        url = "https://releases.example/list",
        base_url = "https://releases.example",
        starts_with = "https://cdn",
        ends_with = r"\.zip") is None


###########################################################
# Cookie backed sessions
###########################################################

@pytest.fixture
def session(monkeypatch, tmp_path):
    state = {"loaded": [], "element": FakeElement(text = "signed in"),
             "saved": [], "cookie_loaded": True, "loads_ok": True}

    def load_url(driver, url, *args, **kwargs):
        state["loaded"].append(url)
        return state["loads_ok"]

    monkeypatch.setattr(webpage, "load_url", load_url)
    monkeypatch.setattr(webpage, "wait_for_element", lambda **kwargs: state["element"])
    monkeypatch.setattr(
        webpage, "save_cookie",
        lambda driver, path, **kwargs: state["saved"].append(path) or True)
    monkeypatch.setattr(webpage, "load_cookie", lambda **kwargs: state["cookie_loaded"])
    return state


def test_a_login_saves_its_cookie(session):
    assert webpage.login_cookie_website(
        FakeDriver(), "https://store.example/login", "/cookies/store.pkl", LOCATOR) is True
    assert session["saved"] == ["/cookies/store.pkl"]


def test_a_login_that_never_signed_in_saves_nothing(session):
    # Saving before the login completed writes a cookie that authenticates
    # nobody, and the next run believes it is signed in.
    session["element"] = None

    assert webpage.login_cookie_website(
        FakeDriver(), "https://store.example/login", "/cookies/store.pkl", LOCATOR) is False
    assert session["saved"] == []


def test_a_login_page_that_will_not_load_saves_nothing(session):
    session["loads_ok"] = False

    assert webpage.login_cookie_website(
        FakeDriver(), "https://store.example/login", "/cookies/store.pkl", LOCATOR) is False
    assert session["saved"] == []


def test_a_cookie_session_loads_the_page_twice(session):
    # The cookie can only be added once the browser is on the site, and it
    # only takes effect on the next load.
    assert webpage.load_cookie_website(
        FakeDriver(), "https://store.example/library", "/cookies/store.pkl") is True
    assert session["loaded"] == [
        "https://store.example/library",
        "https://store.example/library",
    ]


def test_a_cookie_that_will_not_load_stops_the_session(session):
    session["cookie_loaded"] = False

    assert webpage.load_cookie_website(
        FakeDriver(), "https://store.example/library", "/cookies/store.pkl") is False
    assert session["loaded"] == ["https://store.example/library"]
