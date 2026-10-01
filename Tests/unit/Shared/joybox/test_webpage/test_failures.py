# Imports
import json

# Third-party imports
import pytest

# Local imports
from joybox import webpage
from webpage_helpers import (
    BrokenElement, ClickableElement, DyingDriver, FailingDriver, FakeDriver,
    FakeElement, FakeParent)

pytest.importorskip("bs4")
By = pytest.importorskip("selenium.webdriver.common.by").By
exceptions = pytest.importorskip("selenium.common.exceptions")

LOCATOR = webpage.ElementLocator({"css_selector": "div.game"})
COOKIES = [{"name": "session", "value": "abc123", "domain": ".example.com"}]



###########################################################
# Navigation failures
#
# A browser that is still alive can still fail the command it was given.
###########################################################

@pytest.mark.parametrize("verbose", [False, True])
def test_a_page_that_fails_to_load_reports_failure(verbose):
    assert webpage.load_url(FailingDriver(["get"]), "https://x", verbose = verbose) is False


def test_a_page_that_fails_to_load_can_quit_the_program():
    with pytest.raises(SystemExit):
        webpage.load_url(FailingDriver(["get"]), "https://x", exit_on_failure = True)


def test_a_verbose_invalid_url_is_refused():
    assert webpage.load_url(FakeDriver(), "", verbose = True) is False


@pytest.mark.parametrize("verbose", [False, True])
def test_a_session_that_dies_before_its_url_is_read_has_no_url(verbose):
    assert webpage.get_current_page_url(DyingDriver(), verbose = verbose) is None


def test_a_session_check_reads_the_url_once():
    # A second read would see a session that died in between as valid.
    assert webpage.is_session_valid(DyingDriver(reads_before_death = 1)) is True


@pytest.mark.parametrize("verbose", [False, True])
def test_a_session_with_a_blank_url_has_nothing_loaded(verbose):
    assert webpage.is_url_loaded(FakeDriver(url = ""), "https://x", verbose = verbose) is False


@pytest.mark.parametrize("verbose", [False, True])
def test_a_url_that_is_not_text_is_never_loaded(verbose):
    assert webpage.is_url_loaded(FakeDriver(url = 42), "https://x", verbose = verbose) is False


def test_a_verbose_invalid_url_is_never_loaded():
    assert webpage.is_url_loaded(FakeDriver(), None, verbose = True) is False


@pytest.mark.parametrize("obj", [None, FakeDriver(dead = True)])
def test_a_verbose_session_check_reports_the_same_validity(obj):
    assert webpage.is_session_valid(obj, verbose = True) is False


###########################################################
# Scrolling and source failures
###########################################################

def test_a_verbose_scroll_runs_the_script():
    driver = FakeDriver()

    assert webpage.scroll_to_end_of_page(driver, verbose = True) is True
    assert len(driver.scripts) == 1


@pytest.mark.parametrize("verbose", [False, True])
def test_a_scroll_the_page_refuses_reports_failure(verbose):
    assert webpage.scroll_to_end_of_page(FailingDriver(["execute_script"]), verbose = verbose) is False


def test_a_failed_scroll_can_quit_the_program():
    with pytest.raises(SystemExit):
        webpage.scroll_to_end_of_page(FailingDriver(["execute_script"]), exit_on_failure = True)


def test_a_verbose_page_source_is_read():
    assert webpage.get_page_source(FakeDriver(), verbose = True) == "<html><body>page</body></html>"


def test_a_verbose_non_string_url_is_refused():
    assert webpage.get_page_source(FakeDriver(), url = 1, verbose = True) is None


def test_no_source_is_read_from_a_page_that_failed_to_load():
    assert webpage.get_page_source(FailingDriver(["get"]), url = "https://x") is None


@pytest.mark.parametrize("verbose", [False, True])
def test_an_unreadable_page_source_is_absent(verbose):
    assert webpage.get_page_source(FailingDriver(["page_source"]), verbose = verbose) is None


def test_an_unreadable_page_source_can_quit_the_program():
    with pytest.raises(SystemExit):
        webpage.get_page_source(FailingDriver(["page_source"]), exit_on_failure = True)


###########################################################
# Element lookups, verbosely
###########################################################

def test_a_verbose_lookup_finds_the_element():
    found = FakeElement()

    assert webpage.get_element(FakeParent(found = found), LOCATOR, verbose = True) is found


def test_a_verbose_lookup_finds_every_match():
    found = [FakeElement(), FakeElement()]

    assert webpage.get_element(
        FakeParent(found = found), LOCATOR, all_elements = True, verbose = True) == found


@pytest.mark.parametrize("error", [
    exceptions.NoSuchElementException("gone"),
    exceptions.WebDriverException("disconnected"),
    ValueError("unexpected"),
])
def test_a_verbose_failed_lookup_is_absent(error):
    assert webpage.get_element(FakeParent(error = error), LOCATOR, verbose = True) is None


def test_an_expected_lookup_miss_does_not_quit_the_program():
    parent = FakeParent(error = exceptions.NoSuchElementException("gone"))

    assert webpage.get_element(parent, LOCATOR, exit_on_failure = True) is None


@pytest.mark.parametrize("reader", [
    webpage.get_element_text,
    webpage.get_element_children_text,
    webpage.get_element_link_url,
])
def test_a_verbose_reader_of_a_missing_element_reads_nothing(reader):
    assert reader(None, verbose = True) is None


@pytest.mark.parametrize("reader", [webpage.get_element_text, webpage.get_element_children_text])
def test_a_verbose_reader_of_a_stale_element_reads_nothing(reader):
    assert reader(BrokenElement(), verbose = True) is None


@pytest.mark.parametrize("element,name", [
    (None, "href"),
    (FakeElement(), None),
    (BrokenElement(), "href"),
])
def test_a_verbose_unreadable_attribute_is_absent(element, name):
    assert webpage.get_element_attribute(element, name, verbose = True) is None


@pytest.mark.parametrize("verbose", [False, True])
def test_children_text_that_cannot_be_extracted_is_absent(monkeypatch, verbose):
    def broken(html):
        raise ValueError("bad markup")

    monkeypatch.setattr(webpage.text, "extract_web_text", broken)
    element = FakeElement(attributes = {"innerHTML": "<p>x</p>"})

    assert webpage.get_element_children_text(element, verbose = verbose) is None


###########################################################
# Link urls
###########################################################

def test_the_link_url_under_an_element_is_read():
    parent = FakeParent(found = FakeElement(attributes = {"href": "https://store.example/game/1"}))

    assert webpage.get_element_link_url(parent) == "https://store.example/game/1"
    assert parent.lookups == [(By.TAG_NAME, "a")]


def test_an_element_without_a_link_has_no_link_url():
    parent = FakeParent(error = exceptions.NoSuchElementException("no link"))

    assert webpage.get_element_link_url(parent, verbose = True) is None


@pytest.mark.parametrize("verbose", [False, True])
def test_a_failing_link_lookup_has_no_link_url(monkeypatch, verbose):
    def broken(**kwargs):
        raise RuntimeError("lookup failed")

    monkeypatch.setattr(webpage, "get_element", broken)

    assert webpage.get_element_link_url(FakeElement(), verbose = verbose) is None


###########################################################
# Acting on elements, verbosely
###########################################################

def test_a_verbose_click_clicks():
    element = ClickableElement()

    assert webpage.click_element(element, verbose = True) is True
    assert element.clicks == 1


@pytest.mark.parametrize("element", [None, ClickableElement(error = RuntimeError("covered"))])
def test_a_verbose_failed_click_reports_failure(element):
    assert webpage.click_element(element, verbose = True) is False


def test_verbose_keys_are_sent():
    element = ClickableElement()

    assert webpage.send_keys_to_element(element, "text", verbose = True) is True
    assert element.keys == ["text"]


@pytest.mark.parametrize("element,keys", [
    (None, "text"),
    (ClickableElement(), None),
    (ClickableElement(error = RuntimeError("detached")), "text"),
])
def test_verbose_keys_that_are_not_sent_report_failure(element, keys):
    assert webpage.send_keys_to_element(element, keys, verbose = True) is False


###########################################################
# Cookie failures
###########################################################

def test_a_verbose_save_writes_the_cookies(tmp_path):
    target = tmp_path / "store.json"

    assert webpage.save_cookie(FakeDriver(cookies = COOKIES), str(target), verbose = True) is True
    assert json.loads(target.read_text()) == COOKIES


@pytest.mark.parametrize("cookies,path", [([], "store.json"), (COOKIES, "")])
def test_a_verbose_save_with_nothing_to_write_saves_nothing(tmp_path, cookies, path):
    target = str(tmp_path / path) if path else path

    assert webpage.save_cookie(FakeDriver(cookies = cookies), target, verbose = True) is False


@pytest.mark.parametrize("verbose", [False, True])
def test_a_cookie_directory_that_cannot_be_made_saves_nothing(tmp_path, monkeypatch, verbose):
    monkeypatch.setattr(webpage.fileops, "make_directory", lambda **kwargs: False)
    target = tmp_path / "store.json"

    assert webpage.save_cookie(FakeDriver(cookies = COOKIES), str(target), verbose = verbose) is False
    assert not target.exists()


@pytest.mark.parametrize("verbose", [False, True])
def test_cookies_that_cannot_be_written_as_json_are_not_saved(tmp_path, verbose):
    driver = FakeDriver(cookies = [{"name": "session", "value": object()}])

    assert webpage.save_cookie(driver, str(tmp_path / "store.json"), verbose = verbose) is False


def test_a_failed_save_can_quit_the_program(tmp_path):
    driver = FakeDriver(cookies = [{"name": "session", "value": object()}])

    with pytest.raises(SystemExit):
        webpage.save_cookie(driver, str(tmp_path / "store.json"), exit_on_failure = True)


def test_save_options_are_passed_to_the_file_writes(tmp_path, monkeypatch):
    calls = []

    def record(name):
        def call(**kwargs):
            calls.append((name, kwargs))
            return True
        return call

    monkeypatch.setattr(webpage.fileops, "make_directory", record("make_directory"))
    monkeypatch.setattr(webpage.fileops, "touch_file", record("touch_file"))
    target = str(tmp_path / "store.json")

    assert webpage.save_cookie(
        FakeDriver(cookies = COOKIES), target, pretend_run = True, exit_on_failure = True) is True
    for name, kwargs in calls:
        assert (kwargs["pretend_run"], kwargs["exit_on_failure"]) == (True, True), name


def write_cookies(tmp_path, cookies):
    target = tmp_path / "store.json"
    target.write_text(json.dumps(cookies))
    return str(target)


def test_a_verbose_load_adds_the_cookies(tmp_path):
    driver = FakeDriver()

    assert webpage.load_cookie(driver, write_cookies(tmp_path, COOKIES), verbose = True) is True
    assert driver.added_cookies == COOKIES


@pytest.mark.parametrize("cookies", [
    [{"bad": "cookie"}, "not a cookie"],
    [],
])
@pytest.mark.parametrize("verbose", [False, True])
def test_a_cookie_file_with_no_usable_cookies_loads_nothing(tmp_path, cookies, verbose):
    # Reporting success here sends the scraper on as if it were signed in.
    driver = FakeDriver()

    assert webpage.load_cookie(driver, write_cookies(tmp_path, cookies), verbose = verbose) is False
    assert driver.added_cookies == []


def test_pretending_to_load_cookies_succeeds(tmp_path):
    assert webpage.load_cookie(FakeDriver(), write_cookies(tmp_path, COOKIES), pretend_run = True) is True


def test_a_verbose_missing_cookie_file_loads_nothing(tmp_path):
    assert webpage.load_cookie(FakeDriver(), str(tmp_path / "absent.json"), verbose = True) is False


def test_a_verbose_cookie_file_that_is_not_a_list_is_refused(tmp_path):
    assert webpage.load_cookie(FakeDriver(), write_cookies(tmp_path, {"name": "x"}), verbose = True) is False


@pytest.mark.parametrize("verbose", [False, True])
def test_a_cookie_file_that_cannot_be_read_loads_nothing(tmp_path, monkeypatch, verbose):
    def broken(**kwargs):
        raise OSError("disk error")

    monkeypatch.setattr(webpage.serialization, "read_json_file", broken)

    assert webpage.load_cookie(FakeDriver(), write_cookies(tmp_path, COOKIES), verbose = verbose) is False


def test_a_failed_cookie_load_can_quit_the_program(tmp_path, monkeypatch):
    def broken(**kwargs):
        raise OSError("disk error")

    monkeypatch.setattr(webpage.serialization, "read_json_file", broken)

    with pytest.raises(SystemExit):
        webpage.load_cookie(FakeDriver(), write_cookies(tmp_path, COOKIES), exit_on_failure = True)
