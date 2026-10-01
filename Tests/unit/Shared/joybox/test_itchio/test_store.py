# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import itchio


###########################################################
# Construction
###########################################################

def test_an_install_dir_is_required(isolated_settings):
    isolated_settings.set_value("UserData.Itchio", "itchio_install_dir", "")

    with pytest.raises(RuntimeError):
        itchio.Itchio()


def test_the_install_dir_comes_from_settings(itchio_store, tmp_path):
    assert itchio_store.get_install_dir() == os.path.join(str(tmp_path), "itchio")


def test_the_store_describes_itself(itchio_store):
    assert itchio_store.get_name() == config.StoreType.ITCHIO.val()
    assert itchio_store.get_type() == config.StoreType.ITCHIO
    assert itchio_store.get_platform() == config.Platform.COMPUTER_ITCHIO
    assert itchio_store.get_supercategory() == config.Supercategory.ROMS
    assert itchio_store.get_category() == config.Category.COMPUTER
    assert itchio_store.get_subcategory() == config.Subcategory.COMPUTER_ITCHIO
    assert itchio_store.get_key() == config.json_key_itchio
    assert itchio_store.can_import_purchases() and itchio_store.can_download_purchases()


def test_every_identifier_is_the_game_page(itchio_store):
    keys = itchio_store.get_identifier_keys()

    assert set(keys) == set(config.StoreIdentifierType.members())
    assert set(keys.values()) == {config.json_key_store_appurl}


###########################################################
# Logging in
###########################################################

def test_login_waits_for_the_feed_and_saves_the_cookie(itchio_store, browser):
    assert itchio_store.login() is True

    assert browser.loaded == [("https://itch.io/login", itchio_store.get_cookie_file())]
    assert browser.login_locators[0][1] == "My feed"
    assert browser.disconnected == [browser.page]
    assert itchio_store.is_logged_in() is True


def test_login_happens_once(itchio_store, browser):
    itchio_store.login()

    assert itchio_store.login() is True
    assert len(browser.connects) == 1


def test_login_needs_a_browser(itchio_store, browser):
    browser.connect_ok = False

    assert itchio_store.login() is False
    assert itchio_store.is_logged_in() is False


def test_a_failed_login_closes_the_browser_and_is_not_remembered(itchio_store, browser):
    browser.login_ok = False

    assert itchio_store.login() is False
    assert browser.disconnected == [browser.page]
    assert itchio_store.is_logged_in() is False


def test_a_login_that_raises_still_closes_the_browser_once(itchio_store, browser):
    browser.load_error = RuntimeError("session lost")

    with pytest.raises(RuntimeError):
        itchio_store.login()
    assert browser.disconnected == [browser.page]
    assert itchio_store.is_logged_in() is False


def test_a_browser_that_will_not_close_fails_the_login(itchio_store, browser):
    browser.disconnect_ok = False

    assert itchio_store.login() is False
    assert itchio_store.is_logged_in() is False
