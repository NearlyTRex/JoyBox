# Imports
import os

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
    (config.computer_folder_gamedata, config.token_game_install_dir),
    (config.computer_folder_public, config.token_user_public_dir),
    (config.computer_folder_registry, config.token_user_registry_dir),
])
def test_each_general_folder_becomes_its_token(folder, token):
    tokenized = storebase.convert_to_tokenized_path(general(folder, "save"))

    assert tokenized == os.path.join(token, "save")


def test_the_general_root_becomes_the_profile_token():
    tokenized = storebase.convert_to_tokenized_path(general("AppData", "Roaming", "Game"))

    assert tokenized.startswith(config.token_user_profile_dir)


def test_a_store_directory_becomes_the_store_token():
    tokenized = storebase.convert_to_tokenized_path(
        general(config.computer_folder_store, STORE_TYPE, "game"),
        store_type = STORE_TYPE)

    assert tokenized == os.path.join(config.token_store_install_dir, "game")


def test_a_store_directory_is_left_alone_without_a_store_type():
    # Without the store type there is nothing to anchor the replacement on.
    tokenized = storebase.convert_to_tokenized_path(
        general(config.computer_folder_store, STORE_TYPE, "game"))

    assert config.token_store_install_dir not in tokenized


def test_a_user_id_becomes_the_user_token():
    tokenized = storebase.convert_to_tokenized_path(
        general("AppData", STORE_USER_ID, "save"), store_user_id = STORE_USER_ID)

    assert config.token_store_user_id in tokenized
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
    (config.computer_folder_gamedata, config.token_game_install_dir),
    (config.computer_folder_public, config.token_user_public_dir),
    (config.computer_folder_registry, config.token_user_registry_dir),
])
def test_each_token_expands_back_to_its_folder(folder, token):
    expanded = storebase.convert_from_tokenized_path(os.path.join(token, "save"))

    assert expanded == general(folder, "save")


def test_the_profile_token_expands_to_the_general_root():
    expanded = storebase.convert_from_tokenized_path(
        os.path.join(config.token_user_profile_dir, "AppData", "Game"))

    assert expanded == general("AppData", "Game")


def test_the_store_token_expands_with_the_store_type():
    expanded = storebase.convert_from_tokenized_path(
        os.path.join(config.token_store_install_dir, "game"), store_type = STORE_TYPE)

    assert expanded == general(config.computer_folder_store, STORE_TYPE, "game")


def test_the_user_token_expands_to_the_user_id():
    expanded = storebase.convert_from_tokenized_path(
        os.path.join(config.token_user_profile_dir, config.token_store_user_id, "save"),
        store_user_id = STORE_USER_ID)

    assert STORE_USER_ID in expanded
    assert config.token_store_user_id not in expanded


###########################################################
# Round trip
###########################################################

@pytest.mark.parametrize("path", [
    general(config.computer_folder_gamedata, "save"),
    general(config.computer_folder_public, "docs"),
    general(config.computer_folder_registry, "keys"),
    general("AppData", "Roaming", "Game"),
    general("Documents", "My Games", "save.dat"),
])
def test_a_path_survives_the_round_trip(path):
    assert round_trip(path) == paths.normalize_file_path(path)


def test_a_store_path_survives_the_round_trip():
    path = general(config.computer_folder_store, STORE_TYPE, "game", "save")

    assert round_trip(path, store_type = STORE_TYPE) == paths.normalize_file_path(path)


def test_a_user_id_path_survives_the_round_trip():
    path = general("AppData", STORE_USER_ID, "save")

    assert round_trip(path, store_user_id = STORE_USER_ID) == paths.normalize_file_path(path)


def test_a_path_with_every_token_survives_the_round_trip():
    path = general(config.computer_folder_store, STORE_TYPE, STORE_USER_ID, "save")

    assert round_trip(path, store_type = STORE_TYPE, store_user_id = STORE_USER_ID) == \
        paths.normalize_file_path(path)


def test_no_token_survives_expansion():
    # A token left in an expanded path becomes a literal directory name.
    tokenized = storebase.convert_to_tokenized_path(
        general(config.computer_folder_gamedata, "save"))
    expanded = storebase.convert_from_tokenized_path(tokenized)

    for token in [config.token_game_install_dir, config.token_user_profile_dir,
                  config.token_user_public_dir, config.token_user_registry_dir]:
        assert token not in expanded


###########################################################
# Path variants
#
# Callers pass the live list out of a game's json, so appending in place would
# grow the stored paths on every run.
###########################################################

class _Store(storebase.StoreBase):
    def __init__(self):
        pass


def test_variants_are_added_for_each_appdata_form():
    base = next(iter(config.appdata_variants.keys()))
    variants = _Store().add_path_variants([f"USER_PROFILE_DIR{base}Game"])

    assert len(variants) == 1 + len(config.appdata_variants[base])


def test_the_original_path_is_kept():
    base = next(iter(config.appdata_variants.keys()))
    original = f"USER_PROFILE_DIR{base}Game"

    assert original in _Store().add_path_variants([original])


def test_the_caller_list_is_not_modified():
    base = next(iter(config.appdata_variants.keys()))
    original = [f"USER_PROFILE_DIR{base}Game"]
    before = list(original)

    _Store().add_path_variants(original)

    assert original == before


def test_a_games_stored_paths_are_not_modified():
    from joybox import jsondata

    base = next(iter(config.appdata_variants.keys()))
    data = jsondata.JsonData({"store": {"paths": [f"USER_PROFILE_DIR{base}Game"]}})
    live = data.get_subvalue("store", "paths")

    _Store().add_path_variants(live)

    assert data.get_subvalue("store", "paths") == [f"USER_PROFILE_DIR{base}Game"]


def test_no_variants_are_added_for_an_unrelated_path():
    assert _Store().add_path_variants(["somewhere/else"]) == ["somewhere/else"]


def test_no_paths_yields_nothing():
    assert _Store().add_path_variants([]) == []
    assert _Store().add_path_variants() == []


def test_repeated_calls_do_not_accumulate():
    # A shared default would carry results from one call into the next.
    first = _Store().add_path_variants()
    second = _Store().add_path_variants()

    assert first == [] and second == []


###########################################################
# StoreBase
#
# The interface every store implements. The base answers conservatively for
# anything a store has not declared, so an unimplemented capability reads as
# "cannot", not as a crash.
###########################################################

from joybox import config, storebase


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

    assert config.token_user_public_dir in built
    assert config.token_user_profile_dir in built
    assert config.token_store_install_dir in built
    assert config.token_user_registry_dir in built


def test_the_store_token_points_at_the_install_directory():
    built = SampleStore().build_path_translation_map()

    assert built[config.token_store_install_dir] == ["/store/install"]


def test_the_public_token_points_at_the_windows_public_profile():
    built = SampleStore().build_path_translation_map()

    assert "C:\\Users\\Public" in built[config.token_user_public_dir]


def test_the_profile_token_follows_the_environment(monkeypatch):
    monkeypatch.setenv("USERPROFILE", "C:\\Users\\deploy")
    built = SampleStore().build_path_translation_map()

    assert built[config.token_user_profile_dir] == ["C:\\Users\\deploy"]


def test_the_profile_token_is_empty_without_the_environment(monkeypatch):
    monkeypatch.delenv("USERPROFILE", raising = False)
    built = SampleStore().build_path_translation_map()

    assert built[config.token_user_profile_dir] == []


def test_every_token_maps_to_a_list():
    # Callers iterate each entry, so a bare string would iterate characters.
    for value in SampleStore().build_path_translation_map().values():
        assert isinstance(value, list)


def test_a_store_without_an_install_dir_still_builds_a_map():
    built = storebase.StoreBase().build_path_translation_map()

    assert built[config.token_store_install_dir] == [None]
