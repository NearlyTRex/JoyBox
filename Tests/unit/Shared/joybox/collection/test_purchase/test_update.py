# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.collection import purchase
from purchase_helpers import FakeStore, a_purchase


###########################################################
# Updating purchases already in the collection
###########################################################

@pytest.fixture
def updates(collection, monkeypatch, tmp_path):
    json_file = tmp_path / "Half-Life 2.json"
    json_file.write_text("{}")
    collection.update({
        "matches": [str(json_file)],
        "updated_json": [],
        "updated_metadata": [],
        "update_json_ok": True,
        "update_metadata_ok": True,
    })

    def update_game_json_file(**kwargs):
        collection["updated_json"].append(kwargs)
        return collection["update_json_ok"]

    def update_game_metadata_entry(**kwargs):
        collection["updated_metadata"].append(kwargs)
        return collection["update_metadata_ok"]

    monkeypatch.setattr(purchase, "update_game_json_file", update_game_json_file)
    monkeypatch.setattr(purchase, "update_game_metadata_entry", update_game_metadata_entry)
    return collection


def run_update(**kwargs):
    defaults = dict(
        game_supercategory = config.Supercategory.ROMS,
        game_category = config.Category.COMPUTER,
        game_subcategory = config.subcategory_map[config.Category.COMPUTER][0])
    defaults.update(kwargs)
    return purchase.update_game_store_purchases(**defaults)


def test_updating_a_category_without_a_store_is_skipped(updates):
    updates["store"] = None

    assert run_update() is True


def test_updating_a_store_that_cannot_import_is_skipped(updates):
    updates["store"] = FakeStore(can_import = False, purchases = [a_purchase()])

    assert run_update() is True
    assert updates["updated_json"] == []


def test_updating_a_store_with_no_purchases_changes_nothing(updates):
    updates["store"] = FakeStore(purchases = [])

    assert run_update() is True
    assert updates["updated_json"] == []


def test_a_known_purchase_is_refreshed_by_its_game_name(updates):
    updates["store"] = FakeStore(purchases = [a_purchase()])

    assert run_update(keys = ["description"], force = True) is True
    assert updates["updated_json"][0]["game_name"] == "Half-Life 2"
    assert updates["updated_metadata"][0]["game_name"] == "Half-Life 2"
    assert updates["updated_metadata"][0]["keys"] == ["description"]
    assert updates["updated_metadata"][0]["force"] is True


def test_updating_skips_a_purchase_without_an_identifier(updates):
    updates["store"] = FakeStore(purchases = [a_purchase(appid = None)])

    assert run_update() is True
    assert updates["updated_json"] == []


def test_updating_skips_an_ignored_purchase(updates):
    updates["store"] = FakeStore(purchases = [a_purchase(appid = "220")])
    updates["ignores"] = {"220": "Half-Life 2"}

    assert run_update() is True
    assert updates["updated_json"] == []


def test_updating_skips_a_purchase_not_in_the_collection(updates):
    updates["store"] = FakeStore(purchases = [a_purchase()])
    updates["matches"] = []

    assert run_update() is True
    assert updates["updated_json"] == []


def test_a_json_file_that_cannot_be_updated_stops_the_update(updates):
    updates["store"] = FakeStore(purchases = [a_purchase()])
    updates["update_json_ok"] = False

    assert run_update() is False
    assert updates["updated_metadata"] == []


def test_a_metadata_entry_that_cannot_be_updated_stops_the_update(updates):
    updates["store"] = FakeStore(purchases = [a_purchase()])
    updates["update_metadata_ok"] = False

    assert run_update() is False
