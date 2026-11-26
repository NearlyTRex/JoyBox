# Imports
import sys
import types

# Third-party imports
import pytest

# Local imports
from joybox import webpage
from joybox import webfetch
from webpage_helpers import FakeDriver

pytest.importorskip("bs4")


@pytest.fixture
def fetches(monkeypatch):
    # The driver path and a stand-in requests module, each scriptable.
    state = {"driver": FakeDriver(), "source": "<html>driver</html>",
             "source_error": None, "text": "<html>requests</html>", "status": 200,
             "error": None, "destroyed": [], "requests": []}

    def get_page_source(**kwargs):
        error = state["source_error"]
        if error is not None:
            raise error
        return state["source"]

    monkeypatch.setattr(webpage, "create_web_driver", lambda **kwargs: state["driver"])
    monkeypatch.setattr(webpage, "get_page_source", get_page_source)
    monkeypatch.setattr(
        webpage, "destroy_web_driver",
        lambda driver, **kwargs: state["destroyed"].append(driver))

    def raise_for_status():
        if state["status"] >= 400:
            raise RuntimeError("HTTP %d" % state["status"])

    def get(url, params = None, timeout = None):
        state["requests"].append({"url": url, "params": params, "timeout": timeout})
        error = state["error"]
        if error is not None:
            raise error
        return types.SimpleNamespace(
            text = state["text"], status_code = state["status"],
            raise_for_status = raise_for_status)

    module = types.ModuleType("requests")
    module.get = get
    monkeypatch.setitem(sys.modules, "requests", module)
    return state


@pytest.fixture
def page(monkeypatch):
    state = {"html": "", "calls": []}

    def get_website_text(**kwargs):
        state["calls"].append(kwargs)
        return state["html"]

    monkeypatch.setattr(webfetch, "get_website_text", get_website_text)
    return state


def matching(page, html, **kwargs):
    page["html"] = html
    return webfetch.get_matching_urls(
        url = "https://releases.example/list",
        base_url = "https://releases.example",
        **kwargs)


###########################################################
# Fetching a page
###########################################################

def test_a_plain_request_carries_its_params_and_a_timeout(fetches):
    # Without a timeout a stalled server hangs the whole run.
    fetches["driver"] = None
    webfetch.get_website_text("https://store.example", params = {"page": 2})

    assert fetches["requests"] == [{
        "url": "https://store.example", "params": {"page": 2},
        "timeout": webfetch.REQUEST_TIMEOUT_SECONDS}]


def test_an_error_response_is_not_page_text(fetches):
    # A 404 body would otherwise be scraped as if it were the page.
    fetches["driver"] = None
    fetches["status"] = 404
    fetches["text"] = "<html>not found</html>"

    assert webfetch.get_website_text("https://store.example") == ""


def test_the_driver_is_shut_down_when_reading_the_page_quits(fetches):
    fetches["source_error"] = SystemExit(1)

    with pytest.raises(SystemExit):
        webfetch.get_website_text("https://store.example", exit_on_failure = True)
    assert fetches["destroyed"] == [fetches["driver"]]


def test_a_page_nothing_can_fetch_can_quit_the_program(fetches):
    fetches["driver"] = None
    fetches["error"] = OSError("no route to host")

    with pytest.raises(SystemExit):
        webfetch.get_website_text("https://store.example", exit_on_failure = True)


def test_a_fetched_page_does_not_quit_the_program(fetches):
    fetches["driver"] = None

    assert webfetch.get_website_text(
        "https://store.example", exit_on_failure = True) == "<html>requests</html>"


@pytest.mark.parametrize("driver,source,error,expected", [
    (FakeDriver(), "<html>driver</html>", None, "<html>driver</html>"),
    (FakeDriver(), "", None, "<html>requests</html>"),
    (None, "", None, "<html>requests</html>"),
    (None, "", OSError("down"), ""),
])
def test_verbose_fetching_returns_the_same_text(fetches, driver, source, error, expected):
    fetches.update(driver = driver, source = source, error = error)

    assert webfetch.get_website_text(
        "https://store.example", params = {"q": "x"}, verbose = True) == expected
    assert webfetch.get_website_text("https://store.example", verbose = True) == expected


###########################################################
# Matching urls on a page
###########################################################

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

    # A bs4 string subclass would keep the whole parse tree alive.
    assert found == ["https://cdn.example/app.zip"]
    assert [type(url) for url in found] == [str]


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
    return webfetch.get_matching_url(
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
    assert max(names, key = webfetch.get_natural_sort_key) == latest


###########################################################
# Fetching a page
#
# The driver is tried first because store pages render their content with
# javascript, and requests is the fallback for everything simpler.
###########################################################

def test_a_page_is_fetched_with_the_driver(fetches):
    assert webfetch.get_website_text("https://store.example") == "<html>driver</html>"


def test_the_driver_is_shut_down_after_a_fetch(fetches):
    # A driver left running holds a browser process open for the whole run.
    webfetch.get_website_text("https://store.example")

    assert fetches["destroyed"] == [fetches["driver"]]


def test_a_page_falls_back_to_a_plain_request(fetches):
    fetches["driver"] = None

    assert webfetch.get_website_text("https://store.example") == "<html>requests</html>"


def test_an_empty_driver_result_falls_back_to_a_plain_request(fetches):
    fetches["source"] = ""

    assert webfetch.get_website_text("https://store.example") == "<html>requests</html>"


def test_a_page_nothing_can_fetch_is_empty(fetches):
    fetches["driver"] = None
    fetches["error"] = OSError("no route to host")

    assert webfetch.get_website_text("https://store.example") == ""


###########################################################
# Matching urls on a page
###########################################################

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

    found = webfetch.get_matching_url(
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

    found = webfetch.get_matching_url(
        url = "https://releases.example/list",
        base_url = "https://releases.example",
        starts_with = "https://cdn",
        ends_with = r"\.zip",
        get_latest = True)

    assert found == "https://cdn.example/app-3.0.zip"


def test_nothing_matching_yields_nothing(page):
    page["html"] = '<a href="https://cdn.example/app.txt">notes</a>'

    assert webfetch.get_matching_url(
        url = "https://releases.example/list",
        base_url = "https://releases.example",
        starts_with = "https://cdn",
        ends_with = r"\.zip") is None
