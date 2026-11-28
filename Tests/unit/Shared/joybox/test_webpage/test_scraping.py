# Third-party imports
import pytest

# Local imports
from joybox import webpage
from webpage_helpers import LOCATOR, ClickableElement, FakeDriver, FakeElement, FakeParent

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


def test_a_lookup_the_driver_fails_can_quit_the_program():
    parent = FakeParent(error = exceptions.WebDriverException("disconnected"))

    with pytest.raises(SystemExit):
        webpage.get_element(parent, LOCATOR, exit_on_failure = True)


###########################################################
# Waiting for elements
###########################################################


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
