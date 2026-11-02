# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.collection import purchase
from purchase_helpers import FakeStore, a_purchase


###########################################################
# Building purchases
#
# One listing feeds both the import and the update, and a store that cannot
# list its purchases is skipped and named instead of stopping the run.
###########################################################

@pytest.fixture
def steps(monkeypatch):
    state = {"store": FakeStore(purchases = [a_purchase()]), "calls": [], "import_ok": True, "update_ok": True, "warnings": []}
    monkeypatch.setattr(
        purchase.stores, "get_store_by_categories",
        lambda *args, **kwargs: state["store"])
    monkeypatch.setattr(
        purchase, "import_game_store_purchases",
        lambda **kwargs: state["calls"].append(("import", kwargs["purchases"])) or state["import_ok"])
    monkeypatch.setattr(
        purchase, "update_game_store_purchases",
        lambda **kwargs: state["calls"].append(("update", kwargs["purchases"], kwargs["keys"], kwargs["force"])) or state["update_ok"])
    monkeypatch.setattr(purchase.logger, "log_warning", state["warnings"].append)
    return state


def run_build(**kwargs):
    return purchase.build_game_store_purchases(
        config.Supercategory.ROMS,
        config.Category.COMPUTER,
        config.subcategory_map[config.Category.COMPUTER][0],
        **kwargs)


def test_building_imports_then_updates_from_one_listing(steps):
    listed = steps["store"].purchases

    assert run_build(keys = ["k"], force = True) is True
    assert steps["store"].fetches == 1
    assert steps["calls"] == [("import", listed), ("update", listed, ["k"], True)]


def test_a_failed_import_skips_the_update(steps):
    steps["import_ok"] = False

    assert run_build() is False
    assert [call[0] for call in steps["calls"]] == ["import"]


def test_a_failed_update_fails_the_build(steps):
    steps["update_ok"] = False

    assert run_build() is False


def test_building_a_category_without_a_store_does_nothing(steps):
    steps["store"] = None

    assert run_build() is True
    assert steps["calls"] == []


def test_building_a_store_that_cannot_import_does_not_list_it(steps):
    steps["store"] = FakeStore(can_import = False)

    assert run_build() is True
    assert steps["store"].fetches == 0
    assert steps["calls"] == []


def test_a_store_without_a_saved_sign_in_is_skipped_unlisted(steps):
    steps["store"] = FakeStore(saved_login = False)
    skipped = []

    assert run_build(skipped_stores = skipped) is True
    assert steps["store"].fetches == 0
    assert steps["calls"] == []
    assert skipped == ["FakeStore"]
    assert "not signed in" in steps["warnings"][0]
    assert "sign in to FakeStore" in steps["warnings"][0]


def test_a_store_whose_purchases_cannot_be_listed_is_skipped(steps):
    steps["store"] = FakeStore(listable = False)
    skipped = []

    assert run_build(skipped_stores = skipped) is True
    assert steps["calls"] == []
    assert skipped == ["FakeStore"]
    assert "sign-in expired" in steps["warnings"][0]
    assert "sign in to FakeStore" in steps["warnings"][0]


def test_a_store_with_no_purchases_is_not_skipped(steps):
    steps["store"] = FakeStore(purchases = [])
    skipped = []

    assert run_build(skipped_stores = skipped) is True
    assert skipped == []
    assert steps["warnings"] == []


@pytest.fixture
def builds(monkeypatch):
    state = {"visited": [], "ok": True}

    state["skip"] = set()
    state["warnings"] = []

    def build_game_store_purchases(**kwargs):
        state["visited"].append((kwargs["game_category"], kwargs["game_subcategory"]))
        if kwargs["game_subcategory"] in state["skip"]:
            kwargs["skipped_stores"].append(kwargs["game_subcategory"])
        return state["ok"]

    monkeypatch.setattr(purchase, "build_game_store_purchases", build_game_store_purchases)
    monkeypatch.setattr(purchase.logger, "log_warning", state["warnings"].append)
    return state


def test_building_everything_visits_every_subcategory(builds):
    assert purchase.build_all_game_store_purchases() is True
    expected = sum(len(config.subcategory_map[c]) for c in config.Category.members())
    assert len(builds["visited"]) == expected


def test_building_can_be_limited_to_categories(builds):
    assert purchase.build_all_game_store_purchases(categories = [config.Category.COMPUTER]) is True
    assert {category for category, _ in builds["visited"]} == {config.Category.COMPUTER}


def test_building_can_be_limited_to_subcategories(builds):
    subcategory = config.subcategory_map[config.Category.COMPUTER][0]

    assert purchase.build_all_game_store_purchases(subcategories = [subcategory]) is True
    assert builds["visited"] == [(config.Category.COMPUTER, subcategory)]


def test_building_everything_stops_at_the_first_failure(builds):
    builds["ok"] = False

    assert purchase.build_all_game_store_purchases() is False
    assert len(builds["visited"]) == 1


def test_skipped_stores_are_named_once_at_the_end(builds):
    builds["skip"] = {config.Subcategory.COMPUTER_EPIC_GAMES, config.Subcategory.COMPUTER_GOG}

    assert purchase.build_all_game_store_purchases(categories = [config.Category.COMPUTER]) is True
    assert len(builds["warnings"]) == 1
    assert str(config.Subcategory.COMPUTER_EPIC_GAMES) in builds["warnings"][0]
    assert str(config.Subcategory.COMPUTER_GOG) in builds["warnings"][0]


def test_nothing_is_named_when_no_store_was_skipped(builds):
    assert purchase.build_all_game_store_purchases(categories = [config.Category.COMPUTER]) is True
    assert builds["warnings"] == []
