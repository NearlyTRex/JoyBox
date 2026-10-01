# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox.stores import itchio

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def itchio_store(isolated_settings, tmp_path, monkeypatch):
    install_dir = tmp_path / "itchio"
    install_dir.mkdir()
    isolated_settings.set_value("UserData.Itchio", "itchio_install_dir", str(install_dir))
    store = itchio.Itchio()
    monkeypatch.setattr(store, "get_purchases_cache_dir", lambda: str(tmp_path / "cache"))
    return store


@pytest.fixture
def browser(itchio_store, monkeypatch):
    from itchio_helpers import FakeBrowser
    fake = FakeBrowser()

    def web_connect(headless = False, **kwargs):
        fake.connects.append(headless)
        if not fake.connect_ok:
            return None
        return fake.page

    def web_disconnect(web_driver, **kwargs):
        fake.disconnected.append(web_driver)
        return fake.disconnect_ok

    def load_cookie_website(driver, url, cookie, **kwargs):
        fake.load(url, cookie)
        return fake.load_ok

    def login_cookie_website(driver, url, cookie, locator, **kwargs):
        fake.load(url, cookie)
        fake.login_locators.append(locator.get())
        return fake.login_ok

    def wait_for_element(driver, locator, **kwargs):
        return itchio.webpage.get_element(parent = driver, locator = locator)

    def scroll_to_end_of_page(driver, **kwargs):
        fake.scroll()
        return True

    monkeypatch.setattr(itchio_store, "web_connect", web_connect)
    monkeypatch.setattr(itchio_store, "web_disconnect", web_disconnect)
    monkeypatch.setattr(itchio.webpage, "load_cookie_website", load_cookie_website)
    monkeypatch.setattr(itchio.webpage, "login_cookie_website", login_cookie_website)
    monkeypatch.setattr(itchio.webpage, "wait_for_element", wait_for_element)
    monkeypatch.setattr(itchio.webpage, "scroll_to_end_of_page", scroll_to_end_of_page)
    monkeypatch.setattr(itchio.runtime, "sleep_program", lambda seconds: fake.slept.append(seconds))
    monkeypatch.setattr(itchio.datautils.time, "sleep", lambda seconds: None)
    return fake
