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
