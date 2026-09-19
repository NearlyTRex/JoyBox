# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, storepaths


###########################################################
# Path tokenization
#
# Maps the tokens a Ludusavi manifest uses onto JoyBox's own, and the result
# decides which directory gets backed up - a wrong token silently backs up the
# wrong place.
###########################################################

def tokenize(path, base_path = None):
    return storepaths.create_tokenized_path(path, base_path)


@pytest.mark.parametrize("token", ["{UserDir}", "{UserProfile}", "%USERPROFILE%", "%userprofile%", "<home>"])
def test_every_home_token_maps_to_the_profile_directory(token):
    assert tokenize(f"{token}/Docs") == \
        os.path.join(config.token_user_profile_dir, "Docs")


@pytest.mark.parametrize("token", ["{EpicID}", "{EpicId}", "<storeUserId>"])
def test_every_store_user_token_maps_to_the_store_user(token):
    assert tokenize(f"{token}/save") == \
        os.path.join(config.token_store_user_id, "save")


def test_appdata_maps_to_local():
    assert tokenize("{AppData}/Game") == \
        os.path.join(config.token_user_profile_dir, "AppData", "Local", "Game")


def test_appdata_roaming_maps_to_roaming():
    # The "/../Roaming" suffix has to be matched before the bare {AppData}, or
    # it resolves to Local and the wrong directory is backed up.
    assert tokenize("{AppData}/../Roaming/Game") == \
        os.path.join(config.token_user_profile_dir, "AppData", "Roaming", "Game")


def test_appdata_locallow_maps_to_locallow():
    assert tokenize("{AppData}/../LocalLow/Game") == \
        os.path.join(config.token_user_profile_dir, "AppData", "LocalLow", "Game")


@pytest.mark.parametrize("variant", [
    "{AppData}/../Roaming/Game",
    "{appdata}/../roaming/Game",
])
def test_appdata_roaming_is_matched_in_either_case(variant):
    assert "Roaming" in tokenize(variant)


def test_no_traversal_survives_tokenization():
    # A ".." left in the result would escape the backup root.
    for path in ["{AppData}/../Roaming/Game", "{AppData}/../LocalLow/Game"]:
        assert ".." not in tokenize(path)


@pytest.mark.parametrize("token,expected", [
    ("<winDocuments>", "Documents"),
    ("<winAppData>", os.path.join("AppData", "Roaming")),
    ("<winLocalAppData>", os.path.join("AppData", "Local")),
    ("<winAppDataLocalLow>", os.path.join("AppData", "LocalLow")),
])
def test_windows_directory_tokens_expand(token, expected):
    assert tokenize(f"{token}/Game") == \
        os.path.join(config.token_user_profile_dir, expected, "Game")


def test_saved_games_expands():
    assert tokenize("{UserSavedGames}/Game") == \
        os.path.join(config.token_user_profile_dir, "Saved Games", "Game")


def test_the_public_directory_token_expands():
    assert tokenize("<winPublic>/Game") == \
        os.path.join(config.token_user_public_dir, "Game")


def test_the_store_root_token_expands():
    assert tokenize("<root>/Game") == \
        os.path.join(config.token_store_install_dir, "Game")


###########################################################
# Install directory
###########################################################

@pytest.mark.parametrize("token", ["{InstallDir}", "<base>"])
def test_the_install_token_defaults_to_the_game_install_dir(token):
    assert tokenize(f"{token}/save") == \
        os.path.join(config.token_game_install_dir, "save")


@pytest.mark.parametrize("token", ["{InstallDir}", "<base>"])
def test_an_explicit_base_path_replaces_the_install_token(token):
    assert tokenize(f"{token}/save", "/games/mygame") == \
        os.path.join("/games/mygame", "save")


def test_an_invalid_base_path_falls_back_to_the_token():
    assert tokenize("<base>/save", "") == \
        os.path.join(config.token_game_install_dir, "save")


###########################################################
# General shape
###########################################################

def test_a_path_with_no_tokens_is_only_normalized():
    assert tokenize("plain/path/file.sav") == os.path.join("plain", "path", "file.sav")


def test_the_result_is_normalized():
    assert "//" not in tokenize("{AppData}//Game")


def test_no_source_token_survives():
    # An unreplaced token would be treated as a literal directory name.
    for path in ["{AppData}/x", "{UserDir}/x", "{EpicID}/x", "{InstallDir}/x",
                 "{UserSavedGames}/x", "%USERPROFILE%/x"]:
        result = tokenize(path)
        assert "{" not in result and "}" not in result, result
        assert "%" not in result, result


def test_no_angle_token_survives():
    for path in ["<home>/x", "<root>/x", "<base>/x", "<winDocuments>/x",
                 "<winPublic>/x", "<storeUserId>/x"]:
        result = tokenize(path)
        assert "<" not in result and ">" not in result, result
