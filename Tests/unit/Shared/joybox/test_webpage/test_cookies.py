# Imports
import json
import os

# Third-party imports
import pytest

# Local imports
from joybox import webpage
from webpage_helpers import FakeDriver

pytest.importorskip("bs4")



###########################################################
# Cookie files
###########################################################

def test_a_cookie_file_is_placed_in_the_cookie_directory(monkeypatch):
    monkeypatch.setattr(webpage.runtime, "get_cookie_directory", lambda: "/home/user/.cookies")

    assert webpage.get_cookie_file("gog").startswith("/home/user/.cookies")


def test_a_cookie_file_is_named_after_its_site(monkeypatch):
    monkeypatch.setattr(webpage.runtime, "get_cookie_directory", lambda: "/cookies")
    path = webpage.get_cookie_file("gog")

    assert "gog" in path
    assert path.endswith(webpage.config.cookie_suffix_path)


def test_two_sites_get_distinct_cookie_files(monkeypatch):
    monkeypatch.setattr(webpage.runtime, "get_cookie_directory", lambda: "/cookies")

    assert webpage.get_cookie_file("gog") != webpage.get_cookie_file("humblebundle")


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
# Cookies
#
# A saved session is what avoids logging into a store on every scrape.
###########################################################

COOKIES = [
    {"name": "session", "value": "abc123", "domain": ".example.com"},
    {"name": "prefs", "value": "dark", "domain": ".example.com"},
]


def test_cookies_are_saved(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    driver = FakeDriver(cookies = COOKIES)

    assert webpage.save_cookie(driver, str(target)) is True
    assert json.loads(target.read_text()) == COOKIES


def test_saving_creates_the_cookie_directory(tmp_path):
    target = tmp_path / "nested" / ("store" + webpage.config.cookie_suffix_path)
    webpage.save_cookie(FakeDriver(cookies = COOKIES), str(target))

    assert target.exists()


def test_no_cookies_saves_nothing(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)

    assert webpage.save_cookie(FakeDriver(cookies = []), str(target)) is False
    assert not target.exists()


def test_a_dead_session_saves_no_cookies(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)

    assert webpage.save_cookie(FakeDriver(dead = True), str(target)) is False
    assert not target.exists()


@pytest.mark.parametrize("path", [None, ""])
def test_an_invalid_cookie_path_is_refused(path):
    assert webpage.save_cookie(FakeDriver(cookies = COOKIES), path) is False


def test_cookies_are_loaded(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    target.write_text(json.dumps(COOKIES))
    driver = FakeDriver()

    assert webpage.load_cookie(driver, str(target)) is True
    assert driver.added_cookies == COOKIES


def test_a_missing_cookie_file_loads_nothing(tmp_path):
    driver = FakeDriver()

    assert webpage.load_cookie(driver, str(tmp_path / "absent.cookie")) is False
    assert driver.added_cookies == []


def test_a_cookie_file_that_is_not_a_list_is_refused(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    target.write_text(json.dumps({"name": "session"}))

    assert webpage.load_cookie(FakeDriver(), str(target)) is False


def test_one_bad_cookie_does_not_stop_the_rest(tmp_path):
    # An expired or malformed cookie should not cost the whole session.
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    target.write_text(json.dumps([{"bad": "cookie"}] + COOKIES))
    driver = FakeDriver()

    assert webpage.load_cookie(driver, str(target)) is True
    assert driver.added_cookies == COOKIES


def test_a_dead_session_loads_no_cookies(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    target.write_text(json.dumps(COOKIES))
    driver = FakeDriver(dead = True)

    assert webpage.load_cookie(driver, str(target)) is False
    assert driver.added_cookies == []


def test_pretending_loads_no_cookies(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    target.write_text(json.dumps(COOKIES))
    driver = FakeDriver()
    webpage.load_cookie(driver, str(target), pretend_run = True)

    assert driver.added_cookies == []


def test_cookies_survive_a_save_and_load(tmp_path):
    target = tmp_path / ("store" + webpage.config.cookie_suffix_path)
    webpage.save_cookie(FakeDriver(cookies = COOKIES), str(target))
    driver = FakeDriver()
    webpage.load_cookie(driver, str(target))

    assert driver.added_cookies == COOKIES


###########################################################
# Teardown
###########################################################

def test_a_driver_is_destroyed():
    driver = FakeDriver()

    assert webpage.destroy_web_driver(driver) is True
    assert driver.quit_calls == 1


def test_destroying_nothing_is_harmless():
    assert webpage.destroy_web_driver(None) in (True, False)


def test_a_driver_that_fails_to_quit_is_handled():
    class Stubborn(FakeDriver):
        def quit(self):
            raise RuntimeError("already gone")

    assert webpage.destroy_web_driver(Stubborn()) is False


def test_the_generated_cookie_path_is_one_that_can_be_read(tmp_path, monkeypatch):
    # Cookies are written and read as json, and read_json_file refuses a file
    # whose extension does not say so.
    monkeypatch.setattr(webpage.runtime, "get_cookie_directory", lambda: str(tmp_path))
    target = webpage.get_cookie_file("steam")

    assert webpage.save_cookie(FakeDriver(cookies = COOKIES), target) is True
    driver = FakeDriver()
    assert webpage.load_cookie(driver, target) is True
    assert driver.added_cookies == COOKIES
