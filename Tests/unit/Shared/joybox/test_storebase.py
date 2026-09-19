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
