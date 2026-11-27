# Imports

# Third-party imports
import pytest

# Local imports
from joybox import webpage
from webpage_helpers import FakeDriver, FakeElement, FakeParent

pytest.importorskip("bs4")

exceptions = pytest.importorskip("selenium.common.exceptions")



###########################################################
# Driver sessions
#
# A scrape runs against a browser that can die mid-run. Every helper has to
# survive a dead session rather than raising out through the scraper.
###########################################################

###########################################################
# Session validity
###########################################################

def test_a_live_driver_has_a_valid_session():
    assert webpage.is_session_valid(FakeDriver()) is True


def test_a_dead_driver_has_no_valid_session():
    assert webpage.is_session_valid(FakeDriver(dead = True)) is False


def test_no_driver_has_no_valid_session():
    assert webpage.is_session_valid(None) is False


def test_an_object_without_a_url_is_still_valid():
    # Elements are passed through the same check and have no current_url.
    class Bare:
        pass

    assert webpage.is_session_valid(Bare()) is True


###########################################################
# Navigation
###########################################################

def test_a_url_is_loaded():
    driver = FakeDriver()

    assert webpage.load_url(driver, "https://store.example/game") is True
    assert driver.visited == ["https://store.example/game"]


def test_a_dead_session_loads_nothing():
    driver = FakeDriver(dead = True)

    assert webpage.load_url(driver, "https://store.example/game") is False
    assert driver.visited == []


@pytest.mark.parametrize("url", [None, "", 12345, ["https://x"]])
def test_an_invalid_url_is_refused(url):
    driver = FakeDriver()

    assert webpage.load_url(driver, url) is False
    assert driver.visited == []


def test_pretending_navigates_nowhere():
    driver = FakeDriver()

    assert webpage.load_url(driver, "https://x", pretend_run = True) is True
    assert driver.visited == []


def test_the_current_url_is_read():
    assert webpage.get_current_page_url(FakeDriver(url = "https://a/b")) == "https://a/b"


def test_a_dead_session_has_no_current_url():
    assert webpage.get_current_page_url(FakeDriver(dead = True)) is None


def test_a_loaded_url_is_recognised():
    driver = FakeDriver(url = "https://store.example/game?id=1")

    assert webpage.is_url_loaded(driver, "https://store.example/game") is True


def test_a_different_url_is_not_loaded():
    # A redirect to a login page is the case this catches.
    driver = FakeDriver(url = "https://store.example/login")

    assert webpage.is_url_loaded(driver, "https://store.example/game") is False


def test_a_dead_session_has_nothing_loaded():
    assert webpage.is_url_loaded(FakeDriver(dead = True), "https://x") is False


@pytest.mark.parametrize("url", [None, "", 12345])
def test_an_invalid_url_is_never_loaded(url):
    assert webpage.is_url_loaded(FakeDriver(), url) is False


@pytest.mark.parametrize("verbose", [True, False])
@pytest.mark.parametrize("found, expected", [([FakeElement()], True), ([], False)])
def test_a_challenge_page_is_recognised_by_its_error_text(found, expected, verbose):
    driver = FakeParent(found = found)

    assert webpage.is_challenge_page(driver, verbose = verbose) is expected
    assert driver.lookups == [("id", "challenge-error-text")]


def test_a_dead_session_is_not_a_challenge_page():
    assert webpage.is_challenge_page(FakeDriver(dead = True)) is False


@pytest.mark.parametrize("verbose", [True, False])
def test_a_failed_challenge_lookup_is_not_a_challenge_page(verbose):
    assert webpage.is_challenge_page(FakeParent(error = exceptions.WebDriverException("crashed")), verbose = verbose) is False


###########################################################
# Scrolling and source
###########################################################

def test_scrolling_runs_the_scroll_script():
    driver = FakeDriver()

    assert webpage.scroll_to_end_of_page(driver) is True
    assert "scrollHeight" in driver.scripts[0]


def test_a_dead_session_does_not_scroll():
    driver = FakeDriver(dead = True)

    assert webpage.scroll_to_end_of_page(driver) is False
    assert driver.scripts == []


def test_pretending_does_not_scroll():
    driver = FakeDriver()
    webpage.scroll_to_end_of_page(driver, pretend_run = True)

    assert driver.scripts == []


###########################################################
# Teardown
###########################################################

def test_a_driver_is_destroyed():
    driver = FakeDriver()

    assert webpage.destroy_web_driver(driver) is True
    assert driver.quit_calls == 1


def test_destroying_nothing_is_harmless():
    assert webpage.destroy_web_driver(None) is True


def test_a_driver_that_fails_to_quit_is_handled():
    class Stubborn(FakeDriver):
        def quit(self):
            raise exceptions.InvalidSessionIdException("already gone")

    assert webpage.destroy_web_driver(Stubborn()) is False
