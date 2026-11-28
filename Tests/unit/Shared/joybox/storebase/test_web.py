# Third-party imports
import pytest

# Local imports
from joybox import storebase
from joybox.storebase import web


class SampleStore(storebase.StoreBase):

    def get_name(self):
        return "SampleStore"


###########################################################
# Cookie files
###########################################################

def test_a_cookie_file_is_named_after_the_store(monkeypatch):
    monkeypatch.setattr(
        web.webpage.runtime, "get_cookie_directory", lambda: "/cookies")

    assert "samplestore" in SampleStore().get_cookie_file()


def test_two_stores_get_distinct_cookie_files(monkeypatch):
    monkeypatch.setattr(
        web.webpage.runtime, "get_cookie_directory", lambda: "/cookies")

    class OtherStore(SampleStore):
        def get_name(self):
            return "OtherStore"

    assert SampleStore().get_cookie_file() != OtherStore().get_cookie_file()


###########################################################
# Web driver
###########################################################

def test_web_connect_creates_a_driver(monkeypatch):
    calls = []
    monkeypatch.setattr(web.webpage, "create_web_driver", lambda **kwargs: calls.append(kwargs) or "driver")

    assert SampleStore().web_connect(headless = True) == "driver"
    assert calls[0]["make_headless"] is True


def test_web_disconnect_destroys_the_driver(monkeypatch):
    calls = []
    monkeypatch.setattr(web.webpage, "destroy_web_driver", lambda **kwargs: calls.append(kwargs) or True)

    assert SampleStore().web_disconnect("driver") is True
    assert calls[0]["driver"] == "driver"


@pytest.fixture
def drivers(monkeypatch):
    state = {"connect_ok": True, "disconnect_ok": True, "connects": [], "disconnected": []}

    def web_connect(store, headless = False, **kwargs):
        state["connects"].append(headless)
        return "driver-%d" % len(state["connects"]) if state["connect_ok"] else None

    def web_disconnect(store, web_driver, **kwargs):
        state["disconnected"].append(web_driver)
        return state["disconnect_ok"]

    monkeypatch.setattr(SampleStore, "web_connect", web_connect)
    monkeypatch.setattr(SampleStore, "web_disconnect", web_disconnect)
    monkeypatch.setattr(web.webpage.datautils.time, "sleep", lambda seconds: None)
    return state


def test_a_driver_run_returns_the_result_and_disconnects(drivers):
    assert SampleStore().run_with_web_driver(lambda driver: driver + " ok", headless = True) == "driver-1 ok"
    assert drivers["connects"] == [True]
    assert drivers["disconnected"] == ["driver-1"]


def test_a_driver_run_that_cannot_connect_runs_nothing(drivers):
    drivers["connect_ok"] = False
    ran = []

    assert SampleStore().run_with_web_driver(ran.append) is None
    assert ran == []


def test_a_driver_run_that_cannot_disconnect_returns_nothing(drivers):
    drivers["disconnect_ok"] = False

    assert SampleStore().run_with_web_driver(lambda driver: "result") is None


def test_a_driver_run_disconnects_even_when_it_raises(drivers):
    def fail(driver):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        SampleStore().run_with_web_driver(fail)
    assert drivers["disconnected"] == ["driver-1"]


def test_a_scrape_driver_is_headless(drivers):
    assert SampleStore().connect_scrape_driver() == "driver-1"
    assert drivers["connects"] == [True]


def test_a_scrape_driver_that_cannot_start_fails_the_attempt(drivers):
    drivers["connect_ok"] = False

    with pytest.raises(web.webpage.ScrapeFailed):
        SampleStore().connect_scrape_driver()


def test_a_pretend_scrape_driver_that_cannot_start_is_nothing(drivers):
    drivers["connect_ok"] = False

    assert SampleStore().connect_scrape_driver(pretend_run = True) is None


def test_a_scrape_returns_its_result_and_disconnects(drivers):
    assert SampleStore().scrape_with_retries(lambda driver: "page of " + driver, "scrape") == "page of driver-1"
    assert drivers["disconnected"] == ["driver-1"]


def test_a_failed_scrape_attempt_is_retried_on_a_fresh_driver(drivers):
    attempts = []

    def scrape(driver):
        attempts.append(driver)
        if len(attempts) == 1:
            raise web.webpage.ScrapeFailed("not yet")
        return "page"

    assert SampleStore().scrape_with_retries(scrape, "scrape") == "page"
    assert attempts == ["driver-1", "driver-2"]
    assert drivers["disconnected"] == ["driver-1", "driver-2"]


def test_a_pretend_scrape_without_a_driver_scrapes_nothing(drivers):
    drivers["connect_ok"] = False
    scraped = []

    assert SampleStore().scrape_with_retries(scraped.append, "scrape", pretend_run = True) is None
    assert scraped == []
    assert drivers["disconnected"] == []


###########################################################
# Metadata scraping
###########################################################

def test_metadata_is_scraped_with_retries_under_the_store_label(monkeypatch):
    calls = []
    monkeypatch.setattr(SampleStore, "scrape_with_retries", lambda store, scrape_func, operation_name, **kwargs: calls.append(operation_name) or scrape_func("driver"))

    assert SampleStore().scrape_latest_metadata("game", lambda driver: "scraped " + driver, "Sample") == "scraped driver"
    assert calls == ["Sample metadata fetch for 'game'"]


@pytest.mark.parametrize("identifier", ["", None])
def test_an_invalid_metadata_identifier_scrapes_nothing(monkeypatch, identifier):
    scraped = []
    monkeypatch.setattr(web.logger, "log_warning", lambda message: None)

    assert SampleStore().scrape_latest_metadata(identifier, scraped.append, "Sample") is None
    assert scraped == []


def test_a_scrape_page_that_loads_raises_nothing(monkeypatch):
    loaded = []
    monkeypatch.setattr(web.webpage, "load_url", lambda driver, url: loaded.append(url) or True)

    SampleStore().load_scrape_page("driver", "https://example.com/game")
    assert loaded == ["https://example.com/game"]


def test_a_scrape_page_that_does_not_load_fails_the_attempt(monkeypatch):
    monkeypatch.setattr(web.webpage, "load_url", lambda driver, url: False)

    with pytest.raises(web.webpage.ScrapeFailed):
        SampleStore().load_scrape_page("driver", "https://example.com/game")


def test_page_text_is_the_children_text_of_the_located_element(monkeypatch):
    located = []
    monkeypatch.setattr(web.webpage, "wait_for_element", lambda **kwargs: located.append(kwargs["locator"]) or "element")
    monkeypatch.setattr(web.webpage, "get_element_children_text", lambda element: "text of " + element)

    assert SampleStore().wait_for_page_text("driver", {"class": "description"}) == "text of element"
    assert len(located) == 1


def test_page_text_of_a_missing_element_is_nothing(monkeypatch):
    monkeypatch.setattr(web.webpage, "wait_for_element", lambda **kwargs: None)

    assert SampleStore().wait_for_page_text("driver", {"class": "description"}) is None
