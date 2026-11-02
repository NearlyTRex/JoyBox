# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.collection import purchase
from purchase_helpers import FakeStore


###########################################################
# Logging in
###########################################################

class LoginStore(FakeStore):

    def __init__(self, login_result = True):
        super().__init__()
        self.login_result = login_result
        self.login_calls = []

    def login(self, **kwargs):
        self.login_calls.append(kwargs)
        return self.login_result


def test_logging_into_a_category_without_a_store_succeeds(monkeypatch):
    monkeypatch.setattr(purchase.stores, "get_store_by_categories", lambda **kwargs: None)

    assert purchase.login_game_store(
        config.Supercategory.ROMS,
        config.Category.COMPUTER,
        config.subcategory_map[config.Category.COMPUTER][0]) is True


def test_a_store_without_its_own_login_has_nothing_to_log_into(monkeypatch):
    class NoLoginStore(purchase.storebase.StoreBase):
        pass

    monkeypatch.setattr(
        purchase.stores, "get_store_by_categories", lambda **kwargs: NoLoginStore())

    assert purchase.login_game_store(
        config.Supercategory.ROMS,
        config.Category.COMPUTER,
        config.subcategory_map[config.Category.COMPUTER][0]) is True


@pytest.mark.parametrize("result", [True, False])
def test_logging_in_reports_the_stores_result(monkeypatch, result):
    store = LoginStore(login_result = result)
    monkeypatch.setattr(purchase.stores, "get_store_by_categories", lambda **kwargs: store)

    assert purchase.login_game_store(
        config.Supercategory.ROMS,
        config.Category.COMPUTER,
        config.subcategory_map[config.Category.COMPUTER][0],
        verbose = True) is result
    assert store.login_calls[0]["verbose"] is True


def test_logging_into_every_store_visits_every_subcategory(monkeypatch):
    visited = []

    def login_game_store(**kwargs):
        visited.append((kwargs["game_category"], kwargs["game_subcategory"]))
        return True

    monkeypatch.setattr(purchase, "login_game_store", login_game_store)

    assert purchase.login_all_game_stores() is True
    expected = sum(len(config.subcategory_map[c]) for c in config.Category.members())
    assert len(visited) == expected


def test_logging_into_every_store_stops_at_the_first_failure(monkeypatch):
    visited = []

    def login_game_store(**kwargs):
        visited.append(kwargs)
        return False

    monkeypatch.setattr(purchase, "login_game_store", login_game_store)

    assert purchase.login_all_game_stores() is False
    assert len(visited) == 1
