# Third-party imports
import pytest

# Local imports
from joybox import webpage
from webpage_helpers import LOCATOR, FakeDriver

pytest.importorskip("bs4")
exceptions = pytest.importorskip("selenium.common.exceptions")




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
])
def test_a_verbose_failed_wait_finds_nothing(waits, error):
    waits["error"] = error

    assert webpage.wait_for_element(FakeDriver(), LOCATOR, verbose = True) is None


def test_a_wait_the_driver_fails_can_quit_the_program(waits):
    waits["error"] = exceptions.WebDriverException("disconnected")

    with pytest.raises(SystemExit):
        webpage.wait_for_element(FakeDriver(), LOCATOR, exit_on_failure = True)


def test_a_bug_in_a_wait_is_not_taken_for_a_missing_element(waits):
    waits["error"] = ValueError("unexpected")

    with pytest.raises(ValueError):
        webpage.wait_for_element(FakeDriver(), LOCATOR)


def test_a_timed_out_wait_does_not_quit_the_program(waits):
    # A missing element is an ordinary answer, as the readers above treat it.
    waits["error"] = exceptions.TimeoutException("timed out")

    assert webpage.wait_for_element(FakeDriver(), LOCATOR, exit_on_failure = True) is None
