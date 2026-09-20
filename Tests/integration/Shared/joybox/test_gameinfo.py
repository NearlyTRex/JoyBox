# Imports
import json
import os
import pytest

# Local imports
from joybox import config, environment, gameinfo, metadataentry


###########################################################
# GameInfo
#
# The object every command works through. It derives its categories from where
# its json file sits, so a path parsed wrongly gives a game the wrong platform
# and every derived path after that is wrong too.
###########################################################

SUPERCATEGORY = config.Supercategory.ROMS
CATEGORY = config.Category.NINTENDO
SUBCATEGORY = config.Subcategory.NINTENDO_NES
GAME = "Chrono Trigger (USA)"


@pytest.fixture
def tree(tmp_path, monkeypatch):
    # A real metadata, locker and cache layout, since GameInfo reads its json
    # off disk and derives everything else from that path.
    roots = {
        "json": tmp_path / "metadata" / "Json",
        "locker": tmp_path / "locker",
        "cache": tmp_path / "cache",
        "metadata": tmp_path / "metadata",
    }
    for path in roots.values():
        path.mkdir(parents = True, exist_ok = True)

    monkeypatch.setattr(
        environment, "get_game_json_metadata_root_dir", lambda: str(roots["json"]))
    monkeypatch.setattr(
        environment, "get_locker_root_dir", lambda locker_type = None: str(roots["locker"]))
    monkeypatch.setattr(environment, "get_cache_root_dir", lambda: str(roots["cache"]))
    monkeypatch.setattr(
        environment, "get_game_metadata_root_dir", lambda: str(roots["metadata"]))
    monkeypatch.setattr(
        gameinfo.lockerinfo, "get_primary_remote_locker_type", lambda: config.LockerType.LOCAL)
    return roots


def write_game(tree, data = None, name = GAME,
               supercategory = SUPERCATEGORY, category = CATEGORY, subcategory = SUBCATEGORY):
    target = environment.get_game_json_metadata_file(
        supercategory, category, subcategory, name)
    os.makedirs(os.path.dirname(target), exist_ok = True)
    with open(target, "w") as handle:
        handle.write(json.dumps(data if data is not None else {}))
    return target


@pytest.fixture
def game(tree):
    return gameinfo.GameInfo(json_file = write_game(tree))


###########################################################
# Construction
###########################################################

def test_a_game_is_built_from_its_json_file(game):
    assert game.get_name() == GAME


def test_the_categories_come_from_the_path(game):
    assert game.get_supercategory() == SUPERCATEGORY
    assert game.get_category() == CATEGORY
    assert game.get_subcategory() == SUBCATEGORY


def test_the_platform_is_derived_from_the_categories(game):
    assert game.get_platform() is not None
    assert str(SUBCATEGORY) in str(game.get_platform())


def test_a_game_can_be_built_from_its_categories(tree):
    write_game(tree)
    built = gameinfo.GameInfo(
        game_supercategory = SUPERCATEGORY,
        game_category = CATEGORY,
        game_subcategory = SUBCATEGORY,
        game_name = GAME)

    assert built.get_name() == GAME


def test_a_missing_json_file_is_refused(tree):
    # Every command starts here, so failing loudly beats a half built object.
    with pytest.raises(Exception):
        gameinfo.GameInfo(
            game_supercategory = SUPERCATEGORY,
            game_category = CATEGORY,
            game_subcategory = SUBCATEGORY,
            game_name = "Absent Game")


def test_the_json_file_is_remembered(game, tree):
    assert game.get_json_file().endswith(GAME + ".json")
    assert os.path.exists(game.get_json_file())


def test_a_game_in_another_category_derives_that_category(tree):
    other = config.Subcategory.NINTENDO_SNES
    path = write_game(tree, subcategory = other)
    built = gameinfo.GameInfo(json_file = path)

    assert built.get_subcategory() == other


def test_a_game_in_another_supercategory_derives_that_supercategory(tree):
    path = write_game(tree, supercategory = config.Supercategory.DLC)
    built = gameinfo.GameInfo(json_file = path)

    assert built.get_supercategory() == config.Supercategory.DLC


###########################################################
# Deriving categories from a path
###########################################################

def test_a_json_path_derives_its_triple(tree):
    path = write_game(tree)
    derived = gameinfo.derive_game_categories_from_file(path)

    assert derived == (SUPERCATEGORY, CATEGORY, SUBCATEGORY)


def test_a_locker_path_derives_the_same_triple(tree):
    path = environment.get_locker_gaming_files_dir(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)
    derived = gameinfo.derive_game_categories_from_file(
        os.path.join(path, GAME + ".zip"))

    assert derived[:2] == (SUPERCATEGORY, CATEGORY)


@pytest.mark.parametrize("category,subcategory", [
    (config.Category.NINTENDO, config.Subcategory.NINTENDO_NES),
    (config.Category.SONY, config.Subcategory.SONY_PLAYSTATION_3),
    (config.Category.MICROSOFT, config.Subcategory.MICROSOFT_XBOX),
])
def test_each_category_is_recognised(tree, category, subcategory):
    path = write_game(tree, category = category, subcategory = subcategory)
    derived = gameinfo.derive_game_categories_from_file(path)

    assert derived[1] == category
    assert derived[2] == subcategory


def test_an_unrelated_path_derives_nothing(tree):
    assert gameinfo.derive_game_categories_from_file("/tmp/somewhere/game.json") == \
        (None, None, None)


def test_an_invalid_path_derives_nothing():
    assert gameinfo.derive_game_categories_from_file(None) == (None, None, None)


def test_a_path_with_no_subcategory_derives_nothing(tree):
    shallow = os.path.join(
        str(tree["json"]), str(SUPERCATEGORY), str(CATEGORY), "game.json")

    assert gameinfo.derive_game_categories_from_file(shallow) == (None, None, None)


###########################################################
# Values
###########################################################

def test_a_value_is_read(tree):
    built = gameinfo.GameInfo(json_file = write_game(tree, {"appname": "Chrono Trigger"}))

    assert built.get_value("appname") == "Chrono Trigger"


def test_a_missing_value_falls_back(game):
    assert game.get_value("absent") is None
    assert game.get_value("absent", "fallback") == "fallback"


def test_a_subvalue_is_read(tree):
    built = gameinfo.GameInfo(json_file = write_game(tree, {"steam": {"appid": "12345"}}))

    assert built.get_subvalue("steam", "appid") == "12345"


def test_a_missing_subvalue_falls_back(game):
    assert game.get_subvalue("steam", "appid") is None
    assert game.get_subvalue("steam", "appid", "fallback") == "fallback"


def test_key_presence_is_reported(tree):
    built = gameinfo.GameInfo(json_file = write_game(tree, {"steam": {"appid": "12345"}}))

    assert built.has_key("steam") is True
    assert built.has_key("gog") is False
    assert built.has_subkey("steam", "appid") is True
    assert built.has_subkey("steam", "absent") is False


def test_a_value_is_written(game):
    game.set_value("appname", "Chrono Trigger")

    assert game.get_value("appname") == "Chrono Trigger"


def test_a_subvalue_is_written(tree):
    built = gameinfo.GameInfo(json_file = write_game(tree, {"steam": {}}))
    built.set_subvalue("steam", "appid", "12345")

    assert built.get_subvalue("steam", "appid") == "12345"


def test_a_subvalue_needs_its_parent_key_to_exist(game):
    # The parent is not created for you; callers such as set_env_var make it
    # first, and set_default_subvalue checks for it.
    game.set_subvalue("steam", "appid", "12345")

    assert game.has_key("steam") is False


def test_an_existing_subvalue_is_replaced(tree):
    built = gameinfo.GameInfo(json_file = write_game(tree, {"steam": {"appid": "old"}}))
    built.set_subvalue("steam", "appid", "new")

    assert built.get_subvalue("steam", "appid") == "new"


def test_a_sibling_subvalue_is_untouched(tree):
    built = gameinfo.GameInfo(
        json_file = write_game(tree, {"steam": {"appid": "12345", "branchid": "beta"}}))
    built.set_subvalue("steam", "appid", "99999")

    assert built.get_subvalue("steam", "branchid") == "beta"


def test_a_default_value_does_not_overwrite(tree):
    # Filling defaults must not undo what a scrape or the user already set.
    built = gameinfo.GameInfo(json_file = write_game(tree, {"appname": "Existing"}))
    built.set_default_value("appname", "Default")

    assert built.get_value("appname") == "Existing"


def test_a_default_value_fills_a_gap(game):
    game.set_default_value("appname", "Default")

    assert game.get_value("appname") == "Default"


def test_a_default_subvalue_does_not_overwrite(tree):
    built = gameinfo.GameInfo(json_file = write_game(tree, {"steam": {"appid": "12345"}}))
    built.set_default_subvalue("steam", "appid", "99999")

    assert built.get_subvalue("steam", "appid") == "12345"


def test_a_default_subvalue_fills_a_gap(tree):
    built = gameinfo.GameInfo(json_file = write_game(tree, {"steam": {"other": "x"}}))
    built.set_default_subvalue("steam", "appid", "12345")

    assert built.get_subvalue("steam", "appid") == "12345"


def test_a_default_subvalue_needs_its_key_to_exist(game):
    # Without the parent key there is nothing to fill in.
    game.set_default_subvalue("steam", "appid", "12345")

    assert game.get_subvalue("steam", "appid") is None


###########################################################
# Wrapped values
###########################################################

def test_a_wrapped_value_is_a_json_object(tree):
    built = gameinfo.GameInfo(json_file = write_game(tree, {"steam": {"appid": "12345"}}))
    wrapped = built.get_wrapped_value("steam")

    assert wrapped.get_value("appid") == "12345"


def test_a_wrapped_subvalue_is_a_json_object(tree):
    # This raised NameError on every call from a mistyped module reference.
    built = gameinfo.GameInfo(json_file = write_game(tree, {"steam": {"appid": "12345"}}))

    assert built.get_wrapped_subvalue("steam", "appid").get_data() == "12345"


def test_a_wrapped_missing_value_is_still_an_object(game):
    assert game.get_wrapped_value("absent") is not None


###########################################################
# Metadata
###########################################################

def test_a_game_without_metadata_is_not_valid(game):
    # Validity means the collection knows something about the game.
    assert game.has_metadata() is False
    assert game.is_valid() is False


def test_metadata_makes_a_game_valid(game):
    entry = metadataentry.MetadataEntry()
    entry.set_value("genre", "RPG")
    game.set_metadata(entry)

    assert game.has_metadata() is True
    assert game.is_valid() is True


def test_a_metadata_value_is_read(game):
    entry = metadataentry.MetadataEntry()
    entry.set_value("genre", "RPG")
    game.set_metadata(entry)

    assert game.get_metadata_value("genre") == "RPG"


def test_a_metadata_value_is_written(game):
    game.set_metadata(metadataentry.MetadataEntry())
    game.set_metadata_value("genre", "RPG")

    assert game.get_metadata_value("genre") == "RPG"


def test_a_metadata_value_without_metadata_is_nothing(game):
    assert game.get_metadata_value("genre") is None


def test_writing_a_metadata_value_without_metadata_is_refused(game):
    assert game.set_metadata_value("genre", "RPG") is False


def test_a_non_entry_is_not_metadata(game):
    # The key can hold anything; only a real entry counts.
    game.set_value(config.json_key_metadata, {"genre": "RPG"})

    assert game.has_metadata() is False
    assert game.get_metadata() is None


###########################################################
# Assets
###########################################################

ASSET_ACCESSORS = [
    ("get_background_asset", config.AssetType.BACKGROUND),
    ("get_boxback_asset", config.AssetType.BOXBACK),
    ("get_boxfront_asset", config.AssetType.BOXFRONT),
    ("get_label_asset", config.AssetType.LABEL),
    ("get_screenshot_asset", config.AssetType.SCREENSHOT),
    ("get_video_asset", config.AssetType.VIDEO),
]


@pytest.mark.parametrize("accessor,asset_type", ASSET_ACCESSORS)
def test_each_asset_accessor_names_its_own_type(game, accessor, asset_type):
    # A copy-pasted accessor pointing at the wrong type overwrites a different
    # asset on download.
    built = getattr(game, accessor)()

    assert built.endswith(asset_type.cval())
    assert str(asset_type) in built.replace("\\", "/").split("/")


@pytest.mark.parametrize("accessor,asset_type", ASSET_ACCESSORS)
def test_each_asset_is_named_after_the_game(game, accessor, asset_type):
    assert os.path.basename(getattr(game, accessor)()).startswith(GAME)


def test_the_asset_accessors_are_all_distinct(game):
    built = [getattr(game, accessor)() for accessor, _ in ASSET_ACCESSORS]

    assert len(set(built)) == len(ASSET_ACCESSORS)


###########################################################
# Store identifiers
###########################################################

class FakeStore:

    def __init__(self):
        self.asked = []

    def get_key(self):
        return "steam"

    def get_type(self):
        return "Steam"

    def get_install_dir(self):
        return "/steam/steamapps"

    def _key(self, name):
        self.asked.append(name)
        return name

    def get_info_identifier_key(self):
        return self._key("info_id")

    def get_install_identifier_key(self):
        return self._key("install_id")

    def get_launch_identifier_key(self):
        return self._key("launch_id")

    def get_download_identifier_key(self):
        return self._key("download_id")

    def get_asset_identifier_key(self):
        return self._key("asset_id")

    def get_metadata_identifier_key(self):
        return self._key("metadata_id")

    def get_page_identifier_key(self):
        return self._key("page_id")


@pytest.fixture
def store_game(tree, monkeypatch):
    store = FakeStore()
    monkeypatch.setattr(
        gameinfo.stores, "get_store_by_platform", lambda platform, **kwargs: store)
    data = {"steam": {
        "info_id": "info", "install_id": "install", "launch_id": "launch",
        "download_id": "download", "asset_id": "asset",
        "metadata_id": "metadata", "page_id": "page",
    }}
    return gameinfo.GameInfo(json_file = write_game(tree, data)), store


IDENTIFIERS = [
    ("get_store_info_identifier", "info"),
    ("get_store_install_identifier", "install"),
    ("get_store_launch_identifier", "launch"),
    ("get_store_download_identifier", "download"),
    ("get_store_asset_identifier", "asset"),
    ("get_store_metadata_identifier", "metadata"),
    ("get_store_page_identifier", "page"),
]


@pytest.mark.parametrize("accessor,expected", IDENTIFIERS)
def test_each_identifier_reads_its_own_key(store_game, accessor, expected):
    # Seven near identical accessors; one reading a neighbour's key would send
    # the wrong id to the store.
    game, _ = store_game

    assert getattr(game, accessor)() == expected


def test_the_identifiers_are_all_distinct(store_game):
    game, _ = store_game
    built = [getattr(game, accessor)() for accessor, _ in IDENTIFIERS]

    assert len(set(built)) == len(IDENTIFIERS)


def test_the_main_store_key_comes_from_the_store(store_game):
    game, _ = store_game

    assert game.get_main_store_key() == "steam"


def test_the_main_store_type_comes_from_the_store(store_game):
    game, _ = store_game

    assert game.get_main_store_type() == "Steam"


def test_the_main_store_install_dir_comes_from_the_store(store_game):
    game, _ = store_game

    assert game.get_main_store_install_dir() == "/steam/steamapps"


@pytest.mark.parametrize("accessor", [name for name, _ in IDENTIFIERS] + [
    "get_main_store_key", "get_main_store_type", "get_main_store_install_dir"])
def test_a_platform_without_a_store_has_no_identifiers(game, monkeypatch, accessor):
    monkeypatch.setattr(
        gameinfo.stores, "get_store_by_platform", lambda platform, **kwargs: None)

    assert getattr(game, accessor)() is None


###########################################################
# Derived paths
###########################################################

PATH_ACCESSORS = [
    "get_local_cache_dir",
    "get_remote_cache_dir",
    "get_local_rom_dir",
    "get_remote_rom_dir",
    "get_local_save_dir",
    "get_remote_save_dir",
    "get_save_dir",
    "get_general_save_dir",
]


@pytest.mark.parametrize("accessor", PATH_ACCESSORS)
def test_every_derived_path_is_absolute(game, accessor):
    built = getattr(game, accessor)()

    assert built
    assert os.path.isabs(built)


@pytest.mark.parametrize("accessor", PATH_ACCESSORS)
def test_every_derived_path_names_the_game(game, accessor):
    assert GAME in getattr(game, accessor)()


def test_the_local_and_remote_caches_are_separate(game):
    assert game.get_local_cache_dir() != game.get_remote_cache_dir()


def test_the_rom_and_save_directories_are_separate(game):
    assert game.get_local_rom_dir() != game.get_local_save_dir()


def test_a_rom_directory_is_chosen_by_locker(game):
    local = game.get_rom_dir(config.LockerType.LOCAL)

    assert local == game.get_local_rom_dir()


def test_two_games_derive_different_paths(tree):
    first = gameinfo.GameInfo(json_file = write_game(tree, name = "Chrono Trigger (USA)"))
    second = gameinfo.GameInfo(json_file = write_game(tree, name = "Super Metroid (USA)"))

    for accessor in PATH_ACCESSORS:
        assert getattr(first, accessor)() != getattr(second, accessor)()
