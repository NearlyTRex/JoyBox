# Third-party imports
import pytest

# Local imports
from joybox import default_settings
from joybox import webpage
from webpage_helpers import FakeDriver

###########################################################
# Scraping limits
#
# Each limit has a fallback in webpage and a shipped default in the generated
# ini; UserData.Scraping overrides both.
###########################################################

LIMITS = [
    pytest.param(webpage.get_element_wait_seconds, "element_wait_seconds", webpage.default_element_wait_seconds, 1, id = "element-wait"),
    pytest.param(webpage.get_fetch_retries, "fetch_retries", webpage.default_fetch_retries, 1, id = "retries"),
    pytest.param(webpage.get_fetch_retry_delay_seconds, "fetch_retry_delay_seconds", webpage.default_fetch_retry_delay_seconds, 0, id = "retry-delay"),
    pytest.param(webpage.get_min_match_score, "min_match_score", webpage.default_min_match_score, 0, id = "match-score"),
    pytest.param(webpage.get_page_load_interval_seconds, "page_load_interval_seconds", webpage.default_page_load_interval_seconds, 0, id = "page-interval"),
]


@pytest.mark.parametrize("getter, field, fallback, minimum", LIMITS)
def test_a_limit_ships_with_its_fallback_value(isolated_settings, getter, field, fallback, minimum):
    assert default_settings.ini_defaults["UserData.Scraping"][field] == str(fallback)
    assert getter() == fallback


@pytest.mark.parametrize("getter, field, fallback, minimum", LIMITS)
def test_a_limit_follows_the_users_setting(isolated_settings, getter, field, fallback, minimum):
    isolated_settings.set_value("UserData.Scraping", field, str(fallback + 7))

    assert getter() == fallback + 7


@pytest.mark.parametrize("getter, field, fallback, minimum", LIMITS)
def test_a_limit_below_its_minimum_is_raised_to_it(isolated_settings, getter, field, fallback, minimum):
    isolated_settings.set_value("UserData.Scraping", field, "-5")

    assert getter() == minimum


@pytest.mark.parametrize("getter, field, fallback, minimum", LIMITS)
def test_an_unreadable_limit_falls_back(isolated_settings, getter, field, fallback, minimum):
    isolated_settings.set_value("UserData.Scraping", field, "lots")

    assert getter() == fallback


def test_a_wait_without_a_timeout_uses_the_configured_one(isolated_settings, waits):
    isolated_settings.set_value("UserData.Scraping", "element_wait_seconds", "40")

    webpage.wait_for_element(FakeDriver(), webpage.ElementLocator({"id": "x"}))

    assert waits["timeouts"] == [40]


def test_a_scrape_is_retried_with_the_configured_attempts_and_delay(isolated_settings, monkeypatch):
    isolated_settings.set_value("UserData.Scraping", "fetch_retries", "5")
    isolated_settings.set_value("UserData.Scraping", "fetch_retry_delay_seconds", "9")
    calls = []

    def retry_with_backoff(**kwargs):
        calls.append(kwargs)
        return "result"
    monkeypatch.setattr(webpage.datautils, "retry_with_backoff", retry_with_backoff)

    def fetch():
        return None

    def cleanup():
        return None

    assert webpage.retry_scrape(fetch, cleanup, verbose = True, operation_name = "Fetch") == "result"
    assert calls == [{"func": fetch, "cleanup_func": cleanup, "max_retries": 5, "initial_delay": 9,
        "backoff_factor": 2, "verbose": True, "operation_name": "Fetch"}]
