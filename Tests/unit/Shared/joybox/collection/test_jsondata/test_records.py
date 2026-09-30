# Imports
import json
import os

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.collection import jsondata


###########################################################
# Game json files
#
# One json file per game records what the collection holds and where it came
# from. Everything downstream reads it, so a file that is overwritten, or one
# whose file list is wrong, loses what the collection knows about a game.
###########################################################

ROMS = config.Supercategory.ROMS
CATEGORY = config.Category.COMPUTER
SUBCATEGORY = config.subcategory_map[config.Category.COMPUTER][0]
GAME = "Half-Life 2"


@pytest.fixture
def json_root(monkeypatch, tmp_path):
    # The json tree, rooted somewhere disposable.
    root = tmp_path / "json"

    def metadata_file(game_supercategory, game_category, game_subcategory, game_name):
        return str(root / str(game_category) / str(game_subcategory) / (game_name + ".json"))

    def ignore_file(game_supercategory, game_category, game_subcategory):
        return str(root / str(game_category) / str(game_subcategory) / "ignores.json")

    monkeypatch.setattr(
        jsondata.environment, "get_game_json_metadata_file", metadata_file)
    monkeypatch.setattr(
        jsondata.environment, "get_game_json_metadata_ignore_file", ignore_file)
    return root


def json_file(json_root, name = GAME):
    return json_root / str(CATEGORY) / str(SUBCATEGORY) / (name + ".json")


def read_json(path):
    with open(str(path)) as handle:
        return json.load(handle)


###########################################################
# Which categories keep json files
###########################################################

@pytest.mark.parametrize("supercategory", [
    config.Supercategory.ROMS,
    config.Supercategory.DLC,
    config.Supercategory.UPDATES,
])
def test_a_game_supercategory_keeps_json_files(supercategory):
    assert jsondata.are_game_json_file_possible(supercategory) is True


def test_a_supercategory_without_games_keeps_none():
    # Saves and other data are not games and have nothing to record.
    others = [
        member for member in config.Supercategory.members()
        if member not in (config.Supercategory.ROMS,
                          config.Supercategory.DLC,
                          config.Supercategory.UPDATES)
    ]

    for supercategory in others:
        assert jsondata.are_game_json_file_possible(supercategory) is False


###########################################################
# Creating
###########################################################

def test_a_json_file_is_created(json_root):
    assert jsondata.create_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME) is True
    assert json_file(json_root).is_file()


def test_a_created_file_keeps_the_data_it_was_given(json_root):
    jsondata.create_game_json_file(
        ROMS, CATEGORY, SUBCATEGORY, GAME,
        initial_data = {"steam": {"appid": "220"}})

    assert read_json(json_file(json_root))["steam"]["appid"] == "220"


def test_a_created_file_needs_no_initial_data(json_root):
    assert jsondata.create_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME) is True
    assert isinstance(read_json(json_file(json_root)), dict)


def test_creating_makes_the_directories_it_needs(json_root):
    jsondata.create_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME)

    assert json_file(json_root).parent.is_dir()


def test_an_existing_file_is_not_overwritten(json_root):
    # The file holds hand-edited data; recreating it would discard that.
    jsondata.create_game_json_file(
        ROMS, CATEGORY, SUBCATEGORY, GAME, initial_data = {"steam": {"appid": "220"}})

    jsondata.create_game_json_file(
        ROMS, CATEGORY, SUBCATEGORY, GAME, initial_data = {"steam": {"appid": "999"}})

    assert read_json(json_file(json_root))["steam"]["appid"] == "220"


def test_a_category_without_json_files_creates_nothing(json_root):
    saves = [
        member for member in config.Supercategory.members()
        if member not in (config.Supercategory.ROMS,
                          config.Supercategory.DLC,
                          config.Supercategory.UPDATES)
    ][0]

    assert jsondata.create_game_json_file(saves, CATEGORY, SUBCATEGORY, GAME) is True
    assert not json_file(json_root).exists()


###########################################################
# Reading
###########################################################

def test_a_json_file_is_read_back(json_root):
    jsondata.create_game_json_file(
        ROMS, CATEGORY, SUBCATEGORY, GAME, initial_data = {"steam": {"appid": "220"}})

    data = jsondata.read_game_json_data(ROMS, CATEGORY, SUBCATEGORY, GAME)

    assert data is not None
    assert data.get_data()["steam"]["appid"] == "220"


def test_a_missing_json_file_reads_as_nothing(json_root):
    assert jsondata.read_game_json_data(ROMS, CATEGORY, SUBCATEGORY, GAME) is None


def test_a_category_without_json_files_reads_as_nothing(json_root):
    saves = [
        member for member in config.Supercategory.members()
        if member not in (config.Supercategory.ROMS,
                          config.Supercategory.DLC,
                          config.Supercategory.UPDATES)
    ][0]

    assert jsondata.read_game_json_data(saves, CATEGORY, SUBCATEGORY, GAME) is None


def test_a_read_entry_knows_its_platform(json_root):
    jsondata.create_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME)

    data = jsondata.read_game_json_data(ROMS, CATEGORY, SUBCATEGORY, GAME)

    assert data.get_platform()


###########################################################
# Ignore lists
###########################################################

def test_an_ignore_list_starts_empty(json_root):
    assert jsondata.get_game_json_ignore_entries(ROMS, CATEGORY, SUBCATEGORY) == {}


def test_an_ignore_list_is_created_on_first_read(json_root):
    jsondata.get_game_json_ignore_entries(ROMS, CATEGORY, SUBCATEGORY)

    assert (json_root / str(CATEGORY) / str(SUBCATEGORY) / "ignores.json").is_file()


def test_an_ignored_entry_is_recorded(json_root):
    assert jsondata.add_game_json_ignore_entry(
        ROMS, CATEGORY, SUBCATEGORY, "220", GAME) is True

    entries = jsondata.get_game_json_ignore_entries(ROMS, CATEGORY, SUBCATEGORY)
    assert "220" in entries


def test_an_ignored_entry_survives_a_reread(json_root):
    # The list is what stops a declined purchase being offered every run.
    jsondata.add_game_json_ignore_entry(ROMS, CATEGORY, SUBCATEGORY, "220", GAME)

    assert "220" in jsondata.get_game_json_ignore_entries(ROMS, CATEGORY, SUBCATEGORY)


def test_two_ignored_entries_are_both_kept(json_root):
    jsondata.add_game_json_ignore_entry(ROMS, CATEGORY, SUBCATEGORY, "220", GAME)
    jsondata.add_game_json_ignore_entry(ROMS, CATEGORY, SUBCATEGORY, "400", "Portal")

    entries = jsondata.get_game_json_ignore_entries(ROMS, CATEGORY, SUBCATEGORY)

    assert sorted(entries.keys()) == ["220", "400"]


def test_a_category_without_json_files_ignores_nothing(json_root):
    saves = [
        member for member in config.Supercategory.members()
        if member not in (config.Supercategory.ROMS,
                          config.Supercategory.DLC,
                          config.Supercategory.UPDATES)
    ][0]

    assert jsondata.get_game_json_ignore_entries(saves, CATEGORY, SUBCATEGORY) == {}
    assert jsondata.add_game_json_ignore_entry(
        saves, CATEGORY, SUBCATEGORY, "220", GAME) is True


###########################################################
# Updating from what is on disk
#
# The file list is rebuilt from the game's directory, and the sub-folders a
# game ships with decide which key each file lands under.
###########################################################

@pytest.fixture
def game_root(tmp_path):
    root = tmp_path / "games" / GAME
    root.mkdir(parents = True)
    return root


@pytest.fixture
def no_store(monkeypatch):
    # The store lookup reaches the network; the file listing is what is
    # under test here.
    monkeypatch.setattr(
        jsondata.stores, "get_store_by_platform", lambda **kwargs: None)


def write(path, contents = "data"):
    path = str(path)
    os.makedirs(os.path.dirname(path), exist_ok = True)
    with open(path, "w") as handle:
        handle.write(contents)
    return path


def update(json_root, game_root):
    jsondata.create_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME)
    assert jsondata.update_game_json_file(
        ROMS, CATEGORY, SUBCATEGORY, GAME, str(game_root)) is True
    return read_json(json_file(json_root))


def test_the_files_on_disk_are_recorded(json_root, game_root, no_store):
    write(game_root / "game.exe")

    data = update(json_root, game_root)

    assert "game.exe" in data[config.json_key_files]


def test_a_nested_file_is_recorded_with_its_path(json_root, game_root, no_store):
    write(game_root / "data" / "assets.bin")

    data = update(json_root, game_root)

    assert os.path.join("data", "assets.bin") in data[config.json_key_files]


@pytest.mark.parametrize("folder,key", [
    (config.json_key_dlc, config.json_key_dlc),
    (config.json_key_update, config.json_key_update),
    (config.json_key_extra, config.json_key_extra),
    (config.json_key_dependencies, config.json_key_dependencies),
])
def test_each_known_folder_is_recorded_under_its_own_key(json_root, game_root, no_store, folder, key):
    # These folders are installed differently from the game itself, so they
    # cannot be left in the main file list.
    write(game_root / folder / "content.bin")

    data = update(json_root, game_root)

    assert data[key] == ["content.bin"]


def test_a_known_folder_is_kept_out_of_the_main_listing(json_root, game_root, no_store):
    write(game_root / config.json_key_dlc / "content.bin")
    write(game_root / "game.exe")

    data = update(json_root, game_root)

    assert data[config.json_key_dlc] == ["content.bin"]
    assert "game.exe" in data[config.json_key_files]


def test_an_update_of_a_missing_json_file_reports_failure(json_root, game_root, no_store):
    assert jsondata.update_game_json_file(
        ROMS, CATEGORY, SUBCATEGORY, GAME, str(game_root)) is False


def test_a_category_without_json_files_updates_nothing(json_root, game_root, no_store):
    saves = [
        member for member in config.Supercategory.members()
        if member not in (config.Supercategory.ROMS,
                          config.Supercategory.DLC,
                          config.Supercategory.UPDATES)
    ][0]

    assert jsondata.update_game_json_file(
        saves, CATEGORY, SUBCATEGORY, GAME, str(game_root)) is True


def test_an_empty_game_directory_records_no_files(json_root, game_root, no_store):
    data = update(json_root, game_root)

    assert config.json_key_files not in data or data[config.json_key_files] == []
