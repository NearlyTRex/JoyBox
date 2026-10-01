# Third-party imports
import pytest

# Local imports
from joybox import webpage
from webpage_helpers import FakeDriver

pytest.importorskip("bs4")
exceptions = pytest.importorskip("selenium.common.exceptions")

LOCATOR = webpage.ElementLocator({"css_selector": "div.game"})



###########################################################
# Fetching a page
###########################################################

def test_a_plain_request_carries_its_params_and_a_timeout(fetches):
    # Without a timeout a stalled server hangs the whole run.
    fetches["driver"] = None
    webpage.get_website_text("https://store.example", params = {"page": 2})

    assert fetches["requests"] == [{
        "url": "https://store.example", "params": {"page": 2},
        "timeout": webpage.request_timeout_seconds}]


def test_an_error_response_is_not_page_text(fetches):
    # A 404 body would otherwise be scraped as if it were the page.
    fetches["driver"] = None
    fetches["status"] = 404
    fetches["text"] = "<html>not found</html>"

    assert webpage.get_website_text("https://store.example") == ""


def test_the_driver_is_shut_down_when_reading_the_page_quits(fetches):
    fetches["source_error"] = SystemExit(1)

    with pytest.raises(SystemExit):
        webpage.get_website_text("https://store.example", exit_on_failure = True)
    assert fetches["destroyed"] == [fetches["driver"]]


def test_a_page_nothing_can_fetch_can_quit_the_program(fetches):
    fetches["driver"] = None
    fetches["error"] = OSError("no route to host")

    with pytest.raises(SystemExit):
        webpage.get_website_text("https://store.example", exit_on_failure = True)


def test_a_fetched_page_does_not_quit_the_program(fetches):
    fetches["driver"] = None

    assert webpage.get_website_text(
        "https://store.example", exit_on_failure = True) == "<html>requests</html>"


@pytest.mark.parametrize("driver,source,error,expected", [
    (FakeDriver(), "<html>driver</html>", None, "<html>driver</html>"),
    (FakeDriver(), "", None, "<html>requests</html>"),
    (None, "", None, "<html>requests</html>"),
    (None, "", OSError("down"), ""),
])
def test_verbose_fetching_returns_the_same_text(fetches, driver, source, error, expected):
    fetches.update(driver = driver, source = source, error = error)

    assert webpage.get_website_text(
        "https://store.example", params = {"q": "x"}, verbose = True) == expected
    assert webpage.get_website_text("https://store.example", verbose = True) == expected


###########################################################
# Matching urls on a page
###########################################################

def matching(page, html, **kwargs):
    page["html"] = html
    return webpage.get_matching_urls(
        url = "https://releases.example/list",
        base_url = "https://releases.example",
        **kwargs)


def test_a_relative_iframe_is_resolved_against_the_base(page):
    found = matching(page, '<iframe src="/embed/trailer"></iframe>')

    assert "https://releases.example/embed/trailer" in found


def test_an_absolute_iframe_is_kept(page):
    found = matching(page, '<iframe src="https://cdn.example/embed/1"></iframe>')

    assert "https://cdn.example/embed/1" in found


def test_a_link_written_as_padded_text_is_found_without_its_padding(page):
    found = matching(
        page, "<p>\n  https://cdn.example/app-1.0.zip\n</p>",
        starts_with = "https://cdn", ends_with = r"\.zip")

    assert found == ["https://cdn.example/app-1.0.zip"]


def test_matched_text_links_are_plain_strings(page):
    found = matching(page, "<p>https://cdn.example/app.zip</p>", starts_with = "https://cdn")

    assert all(type(url) is str for url in found)


def test_an_empty_href_is_skipped(page):
    assert matching(page, '<a href="">nothing</a>') == []


def test_fetch_options_are_passed_through(page):
    matching(page, "", params = {"q": 1}, verbose = True, pretend_run = True,
             exit_on_failure = True)

    assert page["calls"] == [{
        "url": "https://releases.example/list", "params": {"q": 1},
        "verbose": True, "pretend_run": True, "exit_on_failure": True}]


@pytest.mark.parametrize("verbose", [False, True])
def test_an_unparseable_page_matches_nothing(page, monkeypatch, verbose):
    monkeypatch.setattr(webpage, "parse_html_page_source", lambda text: None)

    assert matching(page, "<html></html>", verbose = verbose) == []


def test_verbose_matching_returns_the_same_urls(page):
    html = '<a href="https://cdn.example/app.zip">x</a><a href="/other">y</a>'

    assert matching(page, html, starts_with = "https://cdn", verbose = True) == \
        matching(page, html, starts_with = "https://cdn")


###########################################################
# Picking one url
###########################################################

def pick(page, html, **kwargs):
    page["html"] = html
    return webpage.get_matching_url(
        url = "https://releases.example/list",
        base_url = "https://releases.example",
        starts_with = "https://cdn",
        ends_with = r"\.zip",
        **kwargs)


def test_the_latest_release_is_ordered_by_number_not_by_digit(page):
    # Compared character by character, 9.0 sorts after 10.0.
    found = pick(page, """
        <a href="https://cdn.example/app-9.0.zip">old</a>
        <a href="https://cdn.example/app-10.0.zip">new</a>
    """, get_latest = True)

    assert found == "https://cdn.example/app-10.0.zip"


def test_the_latest_of_one_release_is_that_release(page):
    assert pick(page, '<a href="https://cdn.example/app.zip">x</a>',
                get_latest = True, verbose = True) == "https://cdn.example/app.zip"


def test_verbose_picking_returns_the_same_url(page):
    html = '<a href="https://cdn.example/a.zip">a</a><a href="https://cdn.example/b.zip">b</a>'

    assert pick(page, html, params = {"q": 1}, verbose = True) == "https://cdn.example/a.zip"


def test_verbose_picking_with_no_match_yields_nothing(page):
    assert pick(page, "<p>none</p>", verbose = True) is None


@pytest.mark.parametrize("names,latest", [
    (["app-1.2.zip", "app-1.10.zip"], "app-1.10.zip"),
    (["App-2.zip", "app-10.zip"], "app-10.zip"),
    (["b.zip", "a.zip"], "b.zip"),
])
def test_natural_ordering_picks_the_highest_name(names, latest):
    assert max(names, key = webpage.get_natural_sort_key) == latest


###########################################################
# Waiting for groups of elements
###########################################################

@pytest.mark.parametrize("waiter", [
    webpage.wait_for_all_elements,
    webpage.wait_for_any_element,
])
@pytest.mark.parametrize("locators", [None, []])
@pytest.mark.parametrize("verbose", [False, True])
def test_a_group_wait_for_nothing_returns_at_once(waits, waiter, locators, verbose):
    # "Any of nothing" never becomes true, so the wait would sit out its
    # whole timeout.
    assert waiter(FakeDriver(), locators, verbose = verbose) is None
    assert waits["timeouts"] == []


@pytest.mark.parametrize("waiter", [
    webpage.wait_for_all_elements,
    webpage.wait_for_any_element,
])
def test_a_group_wait_against_a_dead_session_finds_nothing(waits, waiter):
    assert waiter(FakeDriver(dead = True), [LOCATOR]) is None
    assert waits["timeouts"] == []


@pytest.mark.parametrize("waiter", [
    webpage.wait_for_all_elements,
    webpage.wait_for_any_element,
])
def test_a_verbose_group_wait_returns_the_same_result(waits, waiter):
    assert waiter(FakeDriver(), [LOCATOR, LOCATOR], verbose = True) is waits["result"]


@pytest.mark.parametrize("waiter", [
    webpage.wait_for_all_elements,
    webpage.wait_for_any_element,
])
def test_a_verbose_failed_group_wait_finds_nothing(waits, waiter):
    waits["error"] = exceptions.TimeoutException("timed out")

    assert waiter(FakeDriver(), [LOCATOR], verbose = True) is None


###########################################################
# Waiting for one element
###########################################################

def test_a_verbose_wait_returns_the_element(waits):
    assert webpage.wait_for_element(FakeDriver(), LOCATOR, verbose = True) is waits["result"]


@pytest.mark.parametrize("error", [
    exceptions.TimeoutException("timed out"),
    exceptions.WebDriverException("disconnected"),
    ValueError("unexpected"),
])
def test_a_verbose_failed_wait_finds_nothing(waits, error):
    waits["error"] = error

    assert webpage.wait_for_element(FakeDriver(), LOCATOR, verbose = True) is None


def test_an_unexpected_wait_error_can_quit_the_program(waits):
    waits["error"] = ValueError("unexpected")

    with pytest.raises(SystemExit):
        webpage.wait_for_element(FakeDriver(), LOCATOR, exit_on_failure = True)


def test_a_timed_out_wait_does_not_quit_the_program(waits):
    # A missing element is an ordinary answer, as the readers above treat it.
    waits["error"] = exceptions.TimeoutException("timed out")

    assert webpage.wait_for_element(FakeDriver(), LOCATOR, exit_on_failure = True) is None
