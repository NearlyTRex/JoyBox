# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.collection import purchase
from purchase_helpers import FakeStore, a_purchase


###########################################################
# Importing purchases from a store
#
# Turns a store account's library into json entries in the collection. An
# entry imported twice becomes a duplicate game, and one imported without a
# prompt overrides a decision the user already made.
###########################################################

def run_import(**kwargs):
    defaults = dict(
        game_supercategory = config.Supercategory.ROMS,
        game_category = config.Category.COMPUTER,
        game_subcategory = config.subcategory_map[config.Category.COMPUTER][0])
    defaults.update(kwargs)
    return purchase.import_game_store_purchases(**defaults)


###########################################################
# Nothing to do
###########################################################

def test_a_category_without_a_store_is_skipped(collection):
    collection["store"] = None

    assert run_import() is True


def test_a_store_that_cannot_import_is_skipped(collection):
    collection["store"] = FakeStore(can_import = False)

    assert run_import() is True
    assert collection["created_json"] == []


def test_a_store_with_no_purchases_creates_nothing(collection):
    collection["store"] = FakeStore(purchases = [])

    assert run_import() is True
    assert collection["created_json"] == []


def test_a_given_listing_is_imported_without_asking_the_store(collection):
    store = FakeStore(purchases = [a_purchase(appid = "1"), a_purchase(appid = "2")])
    collection["store"] = store

    assert run_import(purchases = [a_purchase()]) is True
    assert store.fetches == 0
    assert len(collection["created_json"]) == 1


###########################################################
# Importing a new purchase
###########################################################

def test_a_new_purchase_becomes_a_json_entry(collection):
    collection["store"] = FakeStore(purchases = [a_purchase()])

    assert run_import() is True
    assert len(collection["created_json"]) == 1


def test_an_imported_entry_takes_the_chosen_name(collection):
    collection["store"] = FakeStore(purchases = [a_purchase()])
    collection["answers"] = ["y", "Half-Life 2"]

    run_import()

    assert collection["created_json"][0]["game_name"] == "Half-Life 2"


def test_an_imported_entry_carries_the_store_data(collection):
    collection["store"] = FakeStore(purchases = [a_purchase(appid = "220")])

    run_import()

    initial = collection["created_json"][0]["initial_data"]
    assert initial["fakestore"][config.json_key_store_appid] == "220"


def test_an_imported_entry_gets_a_metadata_entry(collection):
    # The json file alone does not make the game visible in the front end.
    collection["store"] = FakeStore(purchases = [a_purchase()])

    run_import()

    assert len(collection["created_metadata"]) == 1


def test_an_imported_entry_is_filed_under_the_stores_categories(collection):
    store = FakeStore(purchases = [a_purchase()])
    collection["store"] = store

    run_import()

    assert collection["created_json"][0]["game_category"] == store.get_category()
    assert collection["created_json"][0]["game_subcategory"] == store.get_subcategory()


###########################################################
# Purchases that are passed over
###########################################################

def test_a_purchase_without_an_identifier_is_skipped(collection):
    # Nothing can be matched against later without one.
    collection["store"] = FakeStore(purchases = [a_purchase(appid = None)])

    assert run_import() is True
    assert collection["created_json"] == []


def test_an_ignored_purchase_is_skipped(collection):
    collection["store"] = FakeStore(purchases = [a_purchase(appid = "220")])
    collection["ignores"] = {"220": "Half-Life 2"}

    run_import()

    assert collection["created_json"] == []


def test_a_purchase_already_in_the_collection_is_skipped(collection):
    # This is what stops every run re-importing the whole library.
    collection["store"] = FakeStore(purchases = [a_purchase()])
    collection["matches"] = ["/json/Half-Life 2.json"]

    run_import()

    assert collection["created_json"] == []


def test_a_purchase_can_be_declined(collection):
    collection["store"] = FakeStore(purchases = [a_purchase()])
    collection["answers"] = ["n"]

    run_import()

    assert collection["created_json"] == []


def test_a_declined_purchase_is_not_ignored_permanently(collection):
    # Declining once should still offer it on the next run; only "i" is final.
    collection["store"] = FakeStore(purchases = [a_purchase()])
    collection["answers"] = ["n"]

    run_import()

    assert collection["added_ignores"] == []


def test_a_purchase_can_be_ignored_permanently(collection):
    collection["store"] = FakeStore(purchases = [a_purchase(appid = "220")])
    collection["answers"] = ["i"]

    run_import()

    assert collection["created_json"] == []
    assert collection["added_ignores"][0]["game_identifier"] == "220"


def test_an_ignore_records_the_name_it_was_offered_as(collection):
    collection["store"] = FakeStore(purchases = [a_purchase(name = "Half-Life 2")])
    collection["answers"] = ["i"]

    run_import()

    assert collection["added_ignores"][0]["game_name"] == "Half-Life 2"


@pytest.mark.parametrize("answer", ["N", "I"])
def test_an_answer_is_read_whatever_its_case(collection, answer):
    collection["store"] = FakeStore(purchases = [a_purchase()])
    collection["answers"] = [answer]

    run_import()

    assert collection["created_json"] == []


###########################################################
# Filling in what the store did not give
###########################################################

def test_a_missing_store_url_is_looked_up(collection):
    collection["store"] = FakeStore(
        purchases = [a_purchase(appurl = None)],
        latest_url = "https://store.example/app/220")

    run_import()

    initial = collection["created_json"][0]["initial_data"]
    assert initial["fakestore"][config.json_key_store_appurl] == \
        "https://store.example/app/220"


def test_a_store_url_that_is_already_known_is_kept(collection):
    collection["store"] = FakeStore(
        purchases = [a_purchase(appurl = "https://store.example/known")],
        latest_url = "https://store.example/looked-up")

    run_import()

    initial = collection["created_json"][0]["initial_data"]
    assert initial["fakestore"][config.json_key_store_appurl] == \
        "https://store.example/known"


def test_a_url_that_cannot_be_found_is_not_fatal(collection):
    collection["store"] = FakeStore(purchases = [a_purchase(appurl = None)], latest_url = None)

    assert run_import() is True
    assert len(collection["created_json"]) == 1


###########################################################
# Failures
###########################################################

def test_a_json_file_that_cannot_be_written_stops_the_import(collection):
    collection["store"] = FakeStore(purchases = [a_purchase()])
    collection["json_ok"] = False

    assert run_import() is False


def test_a_metadata_entry_that_cannot_be_written_stops_the_import(collection):
    collection["store"] = FakeStore(purchases = [a_purchase()])
    collection["metadata_ok"] = False

    assert run_import() is False


def test_a_failed_json_write_does_not_go_on_to_metadata(collection):
    collection["store"] = FakeStore(purchases = [a_purchase()])
    collection["json_ok"] = False

    run_import()

    assert collection["created_metadata"] == []


def test_an_ignore_that_cannot_be_written_stops_the_import(collection, monkeypatch):
    collection["store"] = FakeStore(purchases = [a_purchase()])
    collection["answers"] = ["i"]
    monkeypatch.setattr(purchase, "add_game_json_ignore_entry", lambda **kwargs: False)

    assert run_import() is False


###########################################################
# Purchases with partial store data
###########################################################

def test_a_purchase_offered_by_appname_is_imported(collection):
    collection["store"] = FakeStore(
        purchases = [a_purchase(
            appid = None, appname = "hl2", appurl = "https://store.example/hl2")],
        identifier_key = config.json_key_store_appname)

    assert run_import() is True
    assert len(collection["created_json"]) == 1


def test_a_purchase_without_a_name_takes_the_typed_name(collection):
    collection["store"] = FakeStore(purchases = [a_purchase(name = None)])
    collection["answers"] = ["y", "Typed Name"]

    assert run_import() is True
    assert collection["created_json"][0]["game_name"] == "Typed Name"


def test_a_purchase_without_a_name_is_skipped_when_none_is_typed(collection):
    collection["store"] = FakeStore(purchases = [a_purchase(name = None)])
    collection["answers"] = ["y", ""]

    assert run_import() is True
    assert collection["created_json"] == []


def test_a_purchase_without_a_name_is_not_looked_up_by_name(collection):
    collection["store"] = FakeStore(
        purchases = [a_purchase(name = None)],
        latest_url = "https://store.example/looked-up")
    collection["answers"] = ["y", "Typed Name"]

    run_import()

    initial = collection["created_json"][0]["initial_data"]
    assert initial["fakestore"][config.json_key_store_appurl] is None
