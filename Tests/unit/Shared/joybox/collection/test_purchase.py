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


###########################################################
# Building purchases
###########################################################

def test_building_imports_then_updates(monkeypatch):
    calls = []
    monkeypatch.setattr(
        purchase, "import_game_store_purchases",
        lambda **kwargs: calls.append("import") or True)
    monkeypatch.setattr(
        purchase, "update_game_store_purchases",
        lambda **kwargs: calls.append(("update", kwargs["keys"], kwargs["force"])) or True)

    assert purchase.build_game_store_purchases(
        config.Supercategory.ROMS,
        config.Category.COMPUTER,
        config.subcategory_map[config.Category.COMPUTER][0],
        keys = ["k"],
        force = True) is True
    assert calls == ["import", ("update", ["k"], True)]


def test_a_failed_import_skips_the_update(monkeypatch):
    calls = []
    monkeypatch.setattr(purchase, "import_game_store_purchases", lambda **kwargs: False)
    monkeypatch.setattr(
        purchase, "update_game_store_purchases",
        lambda **kwargs: calls.append("update") or True)

    assert purchase.build_game_store_purchases(
        config.Supercategory.ROMS,
        config.Category.COMPUTER,
        config.subcategory_map[config.Category.COMPUTER][0]) is False
    assert calls == []


def test_a_failed_update_fails_the_build(monkeypatch):
    monkeypatch.setattr(purchase, "import_game_store_purchases", lambda **kwargs: True)
    monkeypatch.setattr(purchase, "update_game_store_purchases", lambda **kwargs: False)

    assert purchase.build_game_store_purchases(
        config.Supercategory.ROMS,
        config.Category.COMPUTER,
        config.subcategory_map[config.Category.COMPUTER][0]) is False


@pytest.fixture
def builds(monkeypatch):
    state = {"visited": [], "ok": True}

    def build_game_store_purchases(**kwargs):
        state["visited"].append((kwargs["game_category"], kwargs["game_subcategory"]))
        return state["ok"]

    monkeypatch.setattr(purchase, "build_game_store_purchases", build_game_store_purchases)
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


###########################################################
# Downloading every purchase
###########################################################

@pytest.fixture
def all_downloads(monkeypatch):
    state = {"names": ["Half-Life 2"], "downloaded": [], "ok": True}

    monkeypatch.setattr(
        purchase.gameinfo, "find_json_game_names",
        lambda supercategory, category, subcategory: (
            state["names"] if category == config.Category.COMPUTER else []))
    monkeypatch.setattr(
        purchase.gameinfo, "GameInfo",
        lambda **kwargs: FakeGameInfo(name = kwargs["game_name"]))

    def download_game_store_purchase(game_info, **kwargs):
        state["downloaded"].append(game_info.get_name())
        return state["ok"]

    monkeypatch.setattr(purchase, "download_game_store_purchase", download_game_store_purchase)
    return state


def test_every_game_in_the_collection_is_downloaded(all_downloads):
    all_downloads["names"] = ["Half-Life 2", "Portal"]

    assert purchase.download_all_game_store_purchases() is True
    subcategories = len(config.subcategory_map[config.Category.COMPUTER])
    assert all_downloads["downloaded"] == ["Half-Life 2", "Portal"] * subcategories


def test_downloading_everything_stops_at_the_first_failure(all_downloads):
    all_downloads["ok"] = False

    assert purchase.download_all_game_store_purchases() is False
    assert all_downloads["downloaded"] == ["Half-Life 2"]
