# Imports
import json
import os
import time

# Third-party imports
import pytest

# Local imports
from joybox import config, paths, storebase


###########################################################
# Tokenized save paths
#
# Store save paths are persisted in a game's json in tokenized form and
# expanded back on use, so the pair has to be a true inverse - a lossy
# round trip points a restore at the wrong directory.
###########################################################

GENERAL = config.SaveType.GENERAL.val()

STORE_TYPE = "Steam"
STORE_USER_ID = "76561190000000000"


def general(*segments):
    return os.path.join(GENERAL, *segments)


def round_trip(path, **kwargs):
    tokenized = storebase.convert_to_tokenized_path(path, **kwargs)
    return storebase.convert_from_tokenized_path(tokenized, **kwargs)


###########################################################
# Tokenizing
###########################################################

@pytest.mark.parametrize("folder,token", [
    (config.COMPUTER_FOLDER_GAMEDATA, config.TOKEN_GAME_INSTALL_DIR),
    (config.COMPUTER_FOLDER_PUBLIC, config.TOKEN_USER_PUBLIC_DIR),
    (config.COMPUTER_FOLDER_REGISTRY, config.TOKEN_USER_REGISTRY_DIR),
])
def test_each_general_folder_becomes_its_token(folder, token):
    tokenized = storebase.convert_to_tokenized_path(general(folder, "save"))

    assert tokenized == os.path.join(token, "save")


def test_the_general_root_becomes_the_profile_token():
    tokenized = storebase.convert_to_tokenized_path(general("AppData", "Roaming", "Game"))

    assert tokenized.startswith(config.TOKEN_USER_PROFILE_DIR)


def test_a_store_directory_becomes_the_store_token():
    tokenized = storebase.convert_to_tokenized_path(
        general(config.COMPUTER_FOLDER_STORE, STORE_TYPE, "game"),
        store_type = STORE_TYPE)

    assert tokenized == os.path.join(config.TOKEN_STORE_INSTALL_DIR, "game")


def test_a_store_directory_is_left_alone_without_a_store_type():
    # Without the store type there is nothing to anchor the replacement on.
    tokenized = storebase.convert_to_tokenized_path(
        general(config.COMPUTER_FOLDER_STORE, STORE_TYPE, "game"))

    assert config.TOKEN_STORE_INSTALL_DIR not in tokenized


def test_a_user_id_becomes_the_user_token():
    tokenized = storebase.convert_to_tokenized_path(
        general("AppData", STORE_USER_ID, "save"), store_user_id = STORE_USER_ID)

    assert config.TOKEN_STORE_USER_ID in tokenized
    assert STORE_USER_ID not in tokenized


def test_a_user_id_is_left_alone_when_not_given():
    tokenized = storebase.convert_to_tokenized_path(general("AppData", STORE_USER_ID, "save"))

    assert STORE_USER_ID in tokenized


def test_a_path_outside_general_is_only_normalized():
    assert storebase.convert_to_tokenized_path("elsewhere/save") == \
        os.path.join("elsewhere", "save")


###########################################################
# Expanding
###########################################################

@pytest.mark.parametrize("folder,token", [
    (config.COMPUTER_FOLDER_GAMEDATA, config.TOKEN_GAME_INSTALL_DIR),
    (config.COMPUTER_FOLDER_PUBLIC, config.TOKEN_USER_PUBLIC_DIR),
    (config.COMPUTER_FOLDER_REGISTRY, config.TOKEN_USER_REGISTRY_DIR),
])
def test_each_token_expands_back_to_its_folder(folder, token):
    expanded = storebase.convert_from_tokenized_path(os.path.join(token, "save"))

    assert expanded == general(folder, "save")


def test_the_profile_token_expands_to_the_general_root():
    expanded = storebase.convert_from_tokenized_path(
        os.path.join(config.TOKEN_USER_PROFILE_DIR, "AppData", "Game"))

    assert expanded == general("AppData", "Game")


def test_the_store_token_expands_with_the_store_type():
    expanded = storebase.convert_from_tokenized_path(
        os.path.join(config.TOKEN_STORE_INSTALL_DIR, "game"), store_type = STORE_TYPE)

    assert expanded == general(config.COMPUTER_FOLDER_STORE, STORE_TYPE, "game")


def test_the_user_token_expands_to_the_user_id():
    expanded = storebase.convert_from_tokenized_path(
        os.path.join(config.TOKEN_USER_PROFILE_DIR, config.TOKEN_STORE_USER_ID, "save"),
        store_user_id = STORE_USER_ID)

    assert STORE_USER_ID in expanded
    assert config.TOKEN_STORE_USER_ID not in expanded


###########################################################
# Round trip
###########################################################

@pytest.mark.parametrize("path", [
    general(config.COMPUTER_FOLDER_GAMEDATA, "save"),
    general(config.COMPUTER_FOLDER_PUBLIC, "docs"),
    general(config.COMPUTER_FOLDER_REGISTRY, "keys"),
    general("AppData", "Roaming", "Game"),
    general("Documents", "My Games", "save.dat"),
])
def test_a_path_survives_the_round_trip(path):
    assert round_trip(path) == paths.normalize_file_path(path)


def test_a_store_path_survives_the_round_trip():
    path = general(config.COMPUTER_FOLDER_STORE, STORE_TYPE, "game", "save")

    assert round_trip(path, store_type = STORE_TYPE) == paths.normalize_file_path(path)


def test_a_user_id_path_survives_the_round_trip():
    path = general("AppData", STORE_USER_ID, "save")

    assert round_trip(path, store_user_id = STORE_USER_ID) == paths.normalize_file_path(path)


def test_a_path_with_every_token_survives_the_round_trip():
    path = general(config.COMPUTER_FOLDER_STORE, STORE_TYPE, STORE_USER_ID, "save")

    assert round_trip(path, store_type = STORE_TYPE, store_user_id = STORE_USER_ID) == \
        paths.normalize_file_path(path)


def test_no_token_survives_expansion():
    # A token left in an expanded path becomes a literal directory name.
    tokenized = storebase.convert_to_tokenized_path(
        general(config.COMPUTER_FOLDER_GAMEDATA, "save"))
    expanded = storebase.convert_from_tokenized_path(tokenized)

    survivors = [
        token for token in [config.TOKEN_GAME_INSTALL_DIR, config.TOKEN_USER_PROFILE_DIR,
                            config.TOKEN_USER_PUBLIC_DIR, config.TOKEN_USER_REGISTRY_DIR]
        if token in expanded]

    assert survivors == []


###########################################################
# Path variants
#
# Callers pass the live list out of a game's json, so appending in place would
# grow the stored paths on every run.
###########################################################

def test_variants_are_added_for_each_appdata_form():
    base = next(iter(config.appdata_variants.keys()))
    variants = storebase.StoreBase().add_path_variants([f"USER_PROFILE_DIR{base}Game"])

    assert len(variants) == 1 + len(config.appdata_variants[base])


def test_the_original_path_is_kept():
    base = next(iter(config.appdata_variants.keys()))
    original = f"USER_PROFILE_DIR{base}Game"

    assert original in storebase.StoreBase().add_path_variants([original])


def test_the_caller_list_is_not_modified():
    base = next(iter(config.appdata_variants.keys()))
    original = [f"USER_PROFILE_DIR{base}Game"]
    before = list(original)

    storebase.StoreBase().add_path_variants(original)

    assert original == before


def test_a_games_stored_paths_are_not_modified():
    from joybox import jsondata

    base = next(iter(config.appdata_variants.keys()))
    data = jsondata.JsonData({"store": {"paths": [f"USER_PROFILE_DIR{base}Game"]}})
    live = data.get_subvalue("store", "paths")

    storebase.StoreBase().add_path_variants(live)

    assert data.get_subvalue("store", "paths") == [f"USER_PROFILE_DIR{base}Game"]


def test_no_variants_are_added_for_an_unrelated_path():
    assert storebase.StoreBase().add_path_variants(["somewhere/else"]) == ["somewhere/else"]


def test_no_paths_yields_nothing():
    assert storebase.StoreBase().add_path_variants([]) == []
    assert storebase.StoreBase().add_path_variants() == []


def test_repeated_calls_do_not_accumulate():
    # A shared default would carry results from one call into the next.
    first = storebase.StoreBase().add_path_variants()
    second = storebase.StoreBase().add_path_variants()

    assert first == [] and second == []


###########################################################
# StoreBase
#
# The interface every store implements. The base answers conservatively for
# anything a store has not declared, so an unimplemented capability reads as
# "cannot", not as a crash.
###########################################################

class SampleStore(storebase.StoreBase):

    def get_name(self):
        return "SampleStore"

    def get_key(self):
        return "teststore"

    def get_install_dir(self):
        return "/store/install"

    def get_identifier_keys(self):
        return {
            config.StoreIdentifierType.INFO: "info_id",
            config.StoreIdentifierType.INSTALL: "install_id",
            config.StoreIdentifierType.LAUNCH: "launch_id",
            config.StoreIdentifierType.DOWNLOAD: "download_id",
            config.StoreIdentifierType.ASSET: "asset_id",
            config.StoreIdentifierType.METADATA: "metadata_id",
            config.StoreIdentifierType.PAGE: "page_id",
        }


###########################################################
# Login state
###########################################################

def test_a_new_store_is_not_logged_in():
    assert storebase.StoreBase().is_logged_in() is False


def test_logging_in_is_recorded():
    # An attribute of the same name as this method makes it uncallable, and
    # every store's login() starts by asking.
    store = storebase.StoreBase()
    store.set_logged_in(True)

    assert store.is_logged_in() is True


def test_logging_out_is_recorded():
    store = storebase.StoreBase()
    store.set_logged_in(True)
    store.set_logged_in(False)

    assert store.is_logged_in() is False


def test_two_stores_do_not_share_login_state():
    first = storebase.StoreBase()
    second = storebase.StoreBase()
    first.set_logged_in(True)

    assert second.is_logged_in() is False


def test_a_subclass_inherits_the_login_state():
    store = SampleStore()

    assert store.is_logged_in() is False
    store.set_logged_in(True)
    assert store.is_logged_in() is True


def test_the_base_login_does_nothing():
    # A store that has not implemented login cannot claim to have logged in.
    assert storebase.StoreBase().login() is False


###########################################################
# Saved sign-in
#
# The purchase step skips a store whose saved sign-in is missing instead of
# running its tool to fail, so a store that cannot be checked must count as
# signed in.
###########################################################

class FileLoginStore(SampleStore):

    def __init__(self, login_files):
        super().__init__()
        self.login_files = login_files

    def get_login_files(self):
        return self.login_files


def test_a_store_that_cannot_be_checked_counts_as_signed_in():
    assert storebase.StoreBase().has_saved_login() is True


def test_a_store_with_every_login_file_is_signed_in(tmp_path):
    login_file = tmp_path / "user.json"
    login_file.write_text("{}")

    assert FileLoginStore([str(login_file)]).has_saved_login() is True


def test_a_missing_login_file_means_not_signed_in(tmp_path):
    present = tmp_path / "user.json"
    present.write_text("{}")

    assert FileLoginStore([str(present), str(tmp_path / "tokens.json")]).has_saved_login() is False


def test_the_login_hint_names_the_store_to_sign_in():
    class ComputerStore(SampleStore):
        def get_category(self):
            return config.Category.COMPUTER
        def get_subcategory(self):
            return config.Subcategory.COMPUTER_EPIC_GAMES

    assert ComputerStore().get_login_hint() == 'login_game_stores -c Computer -s "Epic Games"'


def test_the_user_config_dir_follows_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    assert SampleStore().get_user_config_dir() == str(tmp_path)


def test_the_user_config_dir_defaults_to_dot_config(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising = False)
    monkeypatch.setenv("HOME", str(tmp_path))

    assert SampleStore().get_user_config_dir() == str(tmp_path / ".config")


###########################################################
# Capabilities
###########################################################

CAPABILITIES = [
    "can_handle_installing",
    "can_handle_launching",
    "can_import_purchases",
    "can_download_purchases",
]


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_the_base_claims_no_capability(capability):
    assert getattr(storebase.StoreBase(), capability)() is False


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_an_undeclared_capability_stays_false(capability):
    assert getattr(SampleStore(), capability)() is False


###########################################################
# Identifier keys
###########################################################

IDENTIFIER_ACCESSORS = [
    ("get_info_identifier_key", config.StoreIdentifierType.INFO, "info_id"),
    ("get_install_identifier_key", config.StoreIdentifierType.INSTALL, "install_id"),
    ("get_launch_identifier_key", config.StoreIdentifierType.LAUNCH, "launch_id"),
    ("get_download_identifier_key", config.StoreIdentifierType.DOWNLOAD, "download_id"),
    ("get_asset_identifier_key", config.StoreIdentifierType.ASSET, "asset_id"),
    ("get_metadata_identifier_key", config.StoreIdentifierType.METADATA, "metadata_id"),
    ("get_page_identifier_key", config.StoreIdentifierType.PAGE, "page_id"),
]


@pytest.mark.parametrize("accessor,identifier_type,expected", IDENTIFIER_ACCESSORS)
def test_each_accessor_looks_up_its_own_type(accessor, identifier_type, expected):
    # Seven accessors differing only in the enum they pass through.
    assert getattr(SampleStore(), accessor)() == expected


@pytest.mark.parametrize("accessor,identifier_type,expected", IDENTIFIER_ACCESSORS)
def test_each_accessor_matches_a_direct_lookup(accessor, identifier_type, expected):
    store = SampleStore()

    assert getattr(store, accessor)() == store.get_identifier_key(identifier_type)


def test_the_identifier_types_are_all_covered():
    covered = {identifier_type for _, identifier_type, _ in IDENTIFIER_ACCESSORS}

    assert covered == set(config.StoreIdentifierType.members())


@pytest.mark.parametrize("accessor,identifier_type,expected", IDENTIFIER_ACCESSORS)
def test_a_store_declaring_no_keys_has_none(accessor, identifier_type, expected):
    assert getattr(storebase.StoreBase(), accessor)() is None


def test_an_unknown_identifier_type_has_no_key():
    assert SampleStore().get_identifier_key("not-a-type") is None


###########################################################
# Identifier validity
###########################################################

VALIDATORS = [
    "is_valid_identifier",
    "is_valid_info_identifier",
    "is_valid_install_identifier",
    "is_valid_launch_identifier",
    "is_valid_download_identifier",
    "is_valid_asset_identifier",
    "is_valid_metadata_identifier",
    "is_valid_page_identifier",
]


@pytest.mark.parametrize("validator", VALIDATORS)
def test_a_non_empty_string_is_a_valid_identifier(validator):
    assert getattr(SampleStore(), validator)("12345")


@pytest.mark.parametrize("validator", VALIDATORS)
@pytest.mark.parametrize("identifier", ["", None, 12345, [], {}, ["12345"]])
def test_anything_else_is_not_a_valid_identifier(validator, identifier):
    # An empty or missing id would be sent to the store as a real request.
    assert not getattr(SampleStore(), validator)(identifier)


@pytest.mark.parametrize("validator", VALIDATORS)
def test_whitespace_counts_as_an_identifier(validator):
    # Only emptiness is checked; the store decides what is meaningful.
    assert getattr(SampleStore(), validator)(" ")


###########################################################
# Base defaults
###########################################################

@pytest.mark.parametrize("accessor", [
    "get_name", "get_platform", "get_supercategory",
    "get_category", "get_subcategory", "get_key",
])
def test_an_undeclared_string_field_is_empty(accessor):
    assert getattr(storebase.StoreBase(), accessor)() == ""


@pytest.mark.parametrize("accessor", [
    "get_type", "get_preferred_platform", "get_preferred_architecture",
    "get_account_name", "get_user_name", "get_email", "get_install_dir",
])
def test_an_undeclared_optional_field_is_absent(accessor):
    assert getattr(storebase.StoreBase(), accessor)() is None


def test_the_base_declares_no_identifier_keys():
    assert storebase.StoreBase().get_identifier_keys() == {}


###########################################################
# Cookie files
###########################################################

def test_a_cookie_file_is_named_after_the_store(monkeypatch):
    monkeypatch.setattr(
        storebase.webpage.runtime, "get_cookie_directory", lambda: "/cookies")

    assert "samplestore" in SampleStore().get_cookie_file()


def test_two_stores_get_distinct_cookie_files(monkeypatch):
    monkeypatch.setattr(
        storebase.webpage.runtime, "get_cookie_directory", lambda: "/cookies")

    class OtherStore(SampleStore):
        def get_name(self):
            return "OtherStore"

    assert SampleStore().get_cookie_file() != OtherStore().get_cookie_file()


###########################################################
# Path translation
###########################################################

def test_the_translation_map_covers_the_known_tokens():
    built = SampleStore().build_path_translation_map()

    assert config.TOKEN_USER_PUBLIC_DIR in built
    assert config.TOKEN_USER_PROFILE_DIR in built
    assert config.TOKEN_STORE_INSTALL_DIR in built
    assert config.TOKEN_USER_REGISTRY_DIR in built


def test_the_store_token_points_at_the_install_directory():
    built = SampleStore().build_path_translation_map()

    assert built[config.TOKEN_STORE_INSTALL_DIR] == ["/store/install"]


def test_the_public_token_points_at_the_windows_public_profile():
    built = SampleStore().build_path_translation_map()

    assert "C:\\Users\\Public" in built[config.TOKEN_USER_PUBLIC_DIR]


def test_the_profile_token_follows_the_environment(monkeypatch):
    monkeypatch.setenv("USERPROFILE", "C:\\Users\\deploy")
    built = SampleStore().build_path_translation_map()

    assert built[config.TOKEN_USER_PROFILE_DIR] == ["C:\\Users\\deploy"]


def test_the_profile_token_is_empty_without_the_environment(monkeypatch):
    monkeypatch.delenv("USERPROFILE", raising = False)
    built = SampleStore().build_path_translation_map()

    assert built[config.TOKEN_USER_PROFILE_DIR] == []


def test_every_token_maps_to_a_list():
    # Callers iterate each entry, so a bare string would iterate characters.
    built = SampleStore().build_path_translation_map()
    not_lists = sorted(token for token, value in built.items() if not isinstance(value, list))

    assert not_lists == []


def test_a_store_without_an_install_dir_still_builds_a_map():
    built = storebase.StoreBase().build_path_translation_map()

    assert built[config.TOKEN_STORE_INSTALL_DIR] == [None]


###########################################################
# Unimplemented operations
###########################################################

@pytest.mark.parametrize("operation,args", [
    ("get_latest_url", ["page_id"]),
    ("is_installed", ["install_id"]),
    ("install", ["install_id"]),
    ("uninstall", ["install_id"]),
    ("launch", ["launch_id"]),
    ("download", ["download_id", "/out"]),
])
def test_the_base_operations_do_nothing(operation, args):
    assert not getattr(SampleStore(), operation)(*args)


def test_the_base_store_has_no_purchases():
    assert SampleStore().get_latest_purchases() == []


def test_the_purchases_cache_dir_is_created(monkeypatch, tmp_path):
    cache_dir = str(tmp_path / "Purchases")
    monkeypatch.setattr(storebase.environment, "get_cache_purchases_dir", lambda: cache_dir)

    assert SampleStore().get_purchases_cache_dir() == cache_dir
    assert os.path.isdir(cache_dir)


def write_cache(path, data, age_hours = 0):
    path.write_text(json.dumps(data))
    stamp = time.time() - age_hours * 3600
    os.utime(path, (stamp, stamp))
    return str(path)


def test_a_fresh_purchases_cache_is_read_back(tmp_path):
    cache_file = write_cache(tmp_path / "cache.json", [{"appid": "1"}])

    assert SampleStore().read_purchases_cache(cache_file, "Sample") == [{"appid": "1"}]


def test_a_missing_purchases_cache_is_nothing(tmp_path):
    assert SampleStore().read_purchases_cache(str(tmp_path / "absent.json"), "Sample") is None


def test_a_day_old_purchases_cache_is_ignored(tmp_path):
    cache_file = write_cache(tmp_path / "cache.json", [{"appid": "1"}], age_hours = 25)

    assert SampleStore().read_purchases_cache(cache_file, "Sample") is None


@pytest.mark.parametrize("data", [{"appid": "1"}, ["not a dict"]])
def test_a_malformed_purchases_cache_is_ignored(tmp_path, data):
    cache_file = write_cache(tmp_path / "cache.json", data)

    assert SampleStore().read_purchases_cache(cache_file, "Sample", verbose = True) is None


def test_a_verbose_cache_read_names_the_store(tmp_path, caplog):
    cache_file = write_cache(tmp_path / "cache.json", [])

    SampleStore().read_purchases_cache(cache_file, "Sample Label", verbose = True)

    assert "Using cached Sample Label purchases data" in caplog.text


def test_written_purchases_are_read_back(tmp_path):
    cache_dir = tmp_path / "Purchases"
    cache_file = str(cache_dir / "cache.json")

    SampleStore().write_purchases_cache(str(cache_dir), cache_file, [{"appid": "1"}], "Sample", verbose = True)

    assert SampleStore().read_purchases_cache(cache_file, "Sample") == [{"appid": "1"}]


def test_a_failed_cache_write_is_survived(tmp_path, monkeypatch):
    monkeypatch.setattr(storebase.serialization, "write_json_file", lambda **kwargs: False)

    SampleStore().write_purchases_cache(str(tmp_path), str(tmp_path / "cache.json"), [], "Sample", verbose = True)

    assert not (tmp_path / "cache.json").exists()


def test_purchases_are_wrapped_for_the_store_platform():
    store = SampleStore()

    purchases = store.make_purchases([{config.JSON_KEY_STORE_APPID: "1"}])

    assert [purchase.get_value(config.JSON_KEY_STORE_APPID) for purchase in purchases] == ["1"]
    assert purchases[0].get_platform() == store.get_platform()


###########################################################
# Web driver
###########################################################

def test_web_connect_creates_a_driver(monkeypatch):
    calls = []
    monkeypatch.setattr(storebase.webpage, "create_web_driver", lambda **kwargs: calls.append(kwargs) or "driver")

    assert SampleStore().web_connect(headless = True) == "driver"
    assert calls[0]["make_headless"] is True


def test_web_disconnect_destroys_the_driver(monkeypatch):
    calls = []
    monkeypatch.setattr(storebase.webpage, "destroy_web_driver", lambda **kwargs: calls.append(kwargs) or True)

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
    monkeypatch.setattr(storebase.webpage.datautils.time, "sleep", lambda seconds: None)
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

    with pytest.raises(storebase.webpage.ScrapeFailed):
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
            raise storebase.webpage.ScrapeFailed("not yet")
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
# Downloading through a temporary directory
###########################################################

@pytest.fixture
def archiving(monkeypatch, tmp_path):
    state = {"archived": [], "archive_ok": True, "output": tmp_path / "out"}

    def archive_folder(**kwargs):
        state["archived"].append(kwargs)
        if state["archive_ok"]:
            state["output"].mkdir(exist_ok = True)
            (state["output"] / "game.7z").write_text("x")
        return state["archive_ok"]

    monkeypatch.setattr(storebase.backup, "archive_folder", archive_folder)
    return state


def test_a_fetch_is_archived_into_the_output(archiving):
    fetched = []

    assert SampleStore().download_and_archive(
        lambda download_dir: fetched.append(download_dir) or True, str(archiving["output"]), output_name = "Game") is True
    assert archiving["archived"][0]["input_path"] == fetched[0]
    assert archiving["archived"][0]["output_name"] == "Game"


def test_a_failed_fetch_archives_nothing(archiving):
    assert SampleStore().download_and_archive(lambda download_dir: False, str(archiving["output"])) is False
    assert archiving["archived"] == []


def test_a_failed_archive_fails_the_download(archiving):
    archiving["archive_ok"] = False

    assert SampleStore().download_and_archive(lambda download_dir: True, str(archiving["output"])) is False


def test_a_download_without_a_temporary_directory_fetches_nothing(archiving, monkeypatch):
    monkeypatch.setattr(storebase.fileops, "create_temporary_directory", lambda **kwargs: (False, "no"))
    fetched = []

    assert SampleStore().download_and_archive(fetched.append, str(archiving["output"])) is False
    assert fetched == []


###########################################################
# Latest jsondata, metadata and assets
###########################################################

class NoManifest:
    def find_entry_by_name(self, **kwargs):
        return None


def test_an_invalid_info_identifier_has_no_jsondata():
    assert SampleStore().get_latest_jsondata("") is None


def test_a_valid_info_identifier_gets_default_jsondata(monkeypatch):
    monkeypatch.setattr(storebase.manifest, "get_manifest_instance", NoManifest)
    json_data = SampleStore().get_latest_jsondata("Acme")

    assert json_data.get_value(config.JSON_KEY_STORE_PATHS) == []
    assert json_data.get_value(config.JSON_KEY_STORE_BUILDID) == config.DEFAULT_BUILDID


def test_an_invalid_metadata_identifier_has_no_metadata():
    assert SampleStore().get_latest_metadata("") is None


def test_metadata_is_collected_for_the_identifier(monkeypatch):
    import joybox.metadatacollector as metadatacollector
    calls = []
    monkeypatch.setattr(metadatacollector, "collect_metadata_from_all", lambda **kwargs: calls.append(kwargs) or "entry")

    assert SampleStore().get_latest_metadata("Acme") == "entry"
    assert calls[0]["game_name"] == "Acme"
    assert calls[0]["keys_to_check"] == config.metadata_keys_downloadable


def test_an_invalid_asset_identifier_has_no_asset_url():
    assert SampleStore().get_latest_asset_url("", "boxfront") is None


@pytest.mark.parametrize("game_name,expected", [(None, "acme_id"), ("Acme", "Acme")])
def test_an_asset_is_looked_up_by_game_name_or_identifier(monkeypatch, game_name, expected):
    import joybox.metadataassetcollector as metadataassetcollector
    calls = []
    monkeypatch.setattr(metadataassetcollector, "find_metadata_asset", lambda **kwargs: calls.append(kwargs) or "url")

    assert SampleStore().get_latest_asset_url("acme_id", "boxfront", game_name = game_name) == "url"
    assert calls[0]["game_name"] == expected
    assert calls[0]["asset_type"] == "boxfront"


def test_a_save_path_with_a_folder_nested_in_its_namesake_is_kept(monkeypatch):
    # Installs nest folders under the same name; the path is real, not a doubled join.
    from joybox import jsondata

    class Entry:
        def get_paths(self, base_path):
            return [base_path + "/Saves/Saves/slot1"]
        def get_keys(self):
            return []

    class OneEntryManifest:
        def find_entry_by_name(self, name):
            return Entry()

    monkeypatch.setattr(storebase.manifest, "get_manifest_instance", OneEntryManifest)
    data = jsondata.JsonData({config.JSON_KEY_STORE_PATHS: [], config.JSON_KEY_STORE_KEYS: []})

    augmented = storebase.StoreBase().augment_jsondata(data, "A Game")

    assert augmented.get_value(config.JSON_KEY_STORE_PATHS) == [config.TOKEN_GAME_INSTALL_DIR + "/Saves/Saves/slot1"]
