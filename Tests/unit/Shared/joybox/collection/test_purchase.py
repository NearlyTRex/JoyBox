# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.collection import purchase


###########################################################
# Importing purchases from a store
#
# Turns a store account's library into json entries in the collection. An
# entry imported twice becomes a duplicate game, and one imported without a
# prompt overrides a decision the user already made.
###########################################################

class FakePurchase:

    def __init__(self, **values):
        self.values = dict(values)

    def get_value(self, key):
        return self.values.get(key)

    def set_value(self, key, value):
        self.values[key] = value

    def get_data_copy(self):
        return dict(self.values)


class FakeStore:

    def __init__(
        self,
        purchases = None,
        can_import = True,
        can_download = True,
        identifier_key = config.json_key_store_appid,
        latest_url = None,
        latest_version = "1.0"):
        self.purchases = purchases if purchases is not None else []
        self.can_import = can_import
        self.can_download = can_download
        self.identifier_key = identifier_key
        self.latest_url = latest_url
        self.latest_version = latest_version
        self.downloads = []
        self.logged_in = False

    def get_type(self):
        return "FakeStore"

    def get_key(self):
        return "fakestore"

    def get_supercategory(self):
        return config.Supercategory.ROMS

    def get_category(self):
        return config.Category.COMPUTER

    def get_subcategory(self):
        return config.subcategory_map[config.Category.COMPUTER][0]

    def get_info_identifier_key(self):
        return self.identifier_key

    def can_import_purchases(self):
        return self.can_import

    def can_download_purchases(self):
        return self.can_download

    def get_latest_purchases(self, **kwargs):
        return self.purchases

    def get_latest_url(self, identifier, **kwargs):
        return self.latest_url

    def get_latest_version(self, identifier, **kwargs):
        return self.latest_version

    def download(self, **kwargs):
        self.downloads.append(kwargs)
        return True


def a_purchase(appid = "220", name = "Half-Life 2", appurl = None, appname = None):
    return FakePurchase(**{
        config.json_key_store_appid: appid,
        config.json_key_store_appname: appname,
        config.json_key_store_appurl: appurl,
        config.json_key_store_name: name,
    })


@pytest.fixture
def collection(monkeypatch):
    # Everything the import writes to, recorded rather than written.
    state = {
        "store": FakeStore(),
        "ignores": {},
        "matches": [],
        "answers": ["y", "Chosen Name"],
        "created_json": [],
        "created_metadata": [],
        "added_ignores": [],
        "json_ok": True,
        "metadata_ok": True,
    }

    monkeypatch.setattr(
        purchase.stores, "get_store_by_categories",
        lambda *args, **kwargs: state["store"])
    monkeypatch.setattr(
        purchase, "get_game_json_ignore_entries", lambda **kwargs: state["ignores"])
    monkeypatch.setattr(
        purchase.serialization, "search_json_files", lambda **kwargs: state["matches"])
    monkeypatch.setattr(
        purchase.environment, "get_json_metadata_dir", lambda **kwargs: "/json")
    monkeypatch.setattr(
        purchase.prompts, "prompt_for_value",
        lambda message, default_value = None, **kwargs: (
            state["answers"].pop(0) if state["answers"] else default_value))

    def create_game_json_file(**kwargs):
        state["created_json"].append(kwargs)
        return state["json_ok"]

    def create_game_metadata_entry(**kwargs):
        state["created_metadata"].append(kwargs)
        return state["metadata_ok"]

    def add_game_json_ignore_entry(**kwargs):
        state["added_ignores"].append(kwargs)
        return True

    monkeypatch.setattr(purchase, "create_game_json_file", create_game_json_file)
    monkeypatch.setattr(purchase, "create_game_metadata_entry", create_game_metadata_entry)
    monkeypatch.setattr(purchase, "add_game_json_ignore_entry", add_game_json_ignore_entry)
    return state


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


###########################################################
# Logging in
###########################################################

def test_logging_in_asks_the_store_for_a_login(monkeypatch):
    asked = {}

    def get_store_by_categories(**kwargs):
        asked.update(kwargs)
        return FakeStore()

    monkeypatch.setattr(purchase.stores, "get_store_by_categories", get_store_by_categories)

    assert purchase.login_game_store(
        config.Supercategory.ROMS,
        config.Category.COMPUTER,
        config.subcategory_map[config.Category.COMPUTER][0]) is True
    assert asked["login"] is True


###########################################################
# Downloading a purchase
###########################################################

class FakeGameInfo:

    def __init__(self, name = "Half-Life 2", platform = "Computer"):
        self.name = name
        self.platform = platform

    def get_name(self):
        return self.name

    def get_platform(self):
        return self.platform

    def get_supercategory(self):
        return config.Supercategory.ROMS

    def get_category(self):
        return config.Category.COMPUTER

    def get_subcategory(self):
        return config.subcategory_map[config.Category.COMPUTER][0]

    def get_store_info_identifier(self):
        return "220"

    def get_store_download_identifier(self):
        return "220"

    def get_store_branchid(self):
        return None


@pytest.fixture
def downloads(monkeypatch, tmp_path):
    state = {"store": FakeStore(), "contains_files": False}

    monkeypatch.setattr(
        purchase.stores, "get_store_by_platform", lambda platform: state["store"])
    monkeypatch.setattr(
        purchase.environment, "get_locker_gaming_files_dir",
        lambda **kwargs: str(tmp_path / "locker" / "Half-Life 2"))
    monkeypatch.setattr(
        purchase.environment, "get_locker_gaming_files_offset",
        lambda **kwargs: "Computer/Half-Life 2")
    monkeypatch.setattr(
        purchase.paths, "does_directory_contain_files",
        lambda path: state["contains_files"])
    return state


def test_a_purchase_is_downloaded_into_the_locker(downloads, tmp_path):
    assert purchase.download_game_store_purchase(FakeGameInfo()) is True

    assert downloads["store"].downloads[0]["output_dir"] == \
        str(tmp_path / "locker" / "Half-Life 2")


def test_a_download_is_named_with_its_version(downloads):
    # The version in the name is how a later run notices an update.
    downloads["store"] = FakeStore(latest_version = "2.5")

    purchase.download_game_store_purchase(FakeGameInfo())

    assert downloads["store"].downloads[0]["output_name"] == "Half-Life 2 (2.5)"


def test_a_download_can_be_redirected_outside_the_locker(downloads, tmp_path):
    target = tmp_path / "staging"
    target.mkdir()

    purchase.download_game_store_purchase(FakeGameInfo(), output_dir = str(target))

    assert downloads["store"].downloads[0]["output_dir"].startswith(str(target))


def test_a_redirected_download_keeps_its_collection_layout(downloads, tmp_path):
    target = tmp_path / "staging"
    target.mkdir()

    purchase.download_game_store_purchase(FakeGameInfo(), output_dir = str(target))

    assert downloads["store"].downloads[0]["output_dir"].endswith("Half-Life 2")


def test_a_game_whose_platform_has_no_store_is_not_downloaded(downloads):
    downloads["store"] = None

    assert purchase.download_game_store_purchase(FakeGameInfo()) is False


def test_a_store_that_cannot_download_is_skipped(downloads):
    downloads["store"] = FakeStore(can_download = False)

    assert purchase.download_game_store_purchase(FakeGameInfo()) is True
    assert downloads["store"].downloads == []


def test_an_already_downloaded_purchase_can_be_skipped(downloads):
    # Re-downloading a game is tens of gigabytes.
    downloads["contains_files"] = True

    assert purchase.download_game_store_purchase(
        FakeGameInfo(), skip_existing = True) is True
    assert downloads["store"].downloads == []


def test_an_existing_download_is_replaced_by_default(downloads):
    downloads["contains_files"] = True

    purchase.download_game_store_purchase(FakeGameInfo())

    assert len(downloads["store"].downloads) == 1


def test_a_download_clears_what_was_there_before(downloads):
    # A partial previous download left in place would be mixed with the new.
    purchase.download_game_store_purchase(FakeGameInfo())

    assert downloads["store"].downloads[0]["clean_output"] is True
