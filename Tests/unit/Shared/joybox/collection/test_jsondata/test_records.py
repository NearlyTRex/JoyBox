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


###########################################################
# Encrypted files on disk
###########################################################

RECORDS_PHRASE = "records-phrase"


@pytest.fixture
def locker_phrase(monkeypatch):
    state = {"passphrase": RECORDS_PHRASE}
    monkeypatch.setattr(
        jsondata.lockerinfo.LockerInfo, "get_passphrase", lambda self: state["passphrase"])
    return state


def test_an_encrypted_file_is_recorded_under_its_embedded_name(json_root, game_root, no_store, locker_phrase, monkeypatch):
    write(game_root / "abc.enc")
    monkeypatch.setattr(
        jsondata.cryption, "get_embedded_filename",
        lambda src, passphrase, **kwargs: "game.nes" if passphrase == RECORDS_PHRASE else None)

    data = update(json_root, game_root)

    assert data[config.json_key_files] == ["game.nes"]


def test_without_a_passphrase_files_are_recorded_as_stored(json_root, game_root, no_store, locker_phrase, monkeypatch):
    # Reading an embedded name needs the passphrase, so none is attempted.
    write(game_root / "abc.enc")
    locker_phrase["passphrase"] = None
    monkeypatch.setattr(
        jsondata.cryption, "get_embedded_filename",
        lambda *args, **kwargs: pytest.fail("no embedded name can be read without a passphrase"))

    data = update(json_root, game_root)

    assert data[config.json_key_files] == ["abc.enc"]


###########################################################
# Store data and launch files
###########################################################

def json_path(json_root, category, subcategory, name = GAME):
    return json_root / str(category) / str(subcategory) / (name + ".json")


def update_as(json_root, game_root, supercategory = ROMS, category = CATEGORY, subcategory = SUBCATEGORY):
    jsondata.create_game_json_file(supercategory, category, subcategory, GAME)
    assert jsondata.update_game_json_file(supercategory, category, subcategory, GAME, str(game_root)) is True
    return read_json(json_path(json_root, category, subcategory))


class FakeStore:

    def __init__(self, latest = None):
        self.latest = latest
        self.asked = []

    def get_key(self):
        return "store"

    def get_info_identifier_key(self):
        return config.json_key_store_appid

    def get_latest_jsondata(self, identifier, branch, **kwargs):
        self.asked.append((identifier, branch))
        return self.latest


@pytest.fixture
def store(monkeypatch):
    holder = {"store": FakeStore()}
    monkeypatch.setattr(jsondata.stores, "get_store_by_platform", lambda **kwargs: holder["store"])
    return holder


def latest(**values):
    from joybox import jsondata as jsondata_module
    return jsondata_module.JsonData(json_data = dict(values), json_platform = None)


def test_a_manually_imported_game_gets_generated_store_ids(json_root, game_root, store, monkeypatch):
    monkeypatch.setattr(jsondata.strings, "generate_unique_id", lambda: "unique-id")
    zoom = config.Subcategory.COMPUTER_ZOOM

    data = update_as(json_root, game_root, subcategory = zoom)

    assert data["store"][config.json_key_store_appid] == "unique-id"
    assert data["store"][config.json_key_store_appname] == jsondata.strings.get_slug_string(GAME)
    assert data["store"][config.json_key_store_name] == GAME
    assert store["store"].asked == [("unique-id", None)]


def test_latest_store_data_is_merged_under_the_store_key(json_root, game_root, store):
    write(json_path(json_root, CATEGORY, SUBCATEGORY), json.dumps({
        "store": {config.json_key_store_appid: "220", config.json_key_store_branchid: "beta"}}))
    store["store"].latest = latest(**{
        config.json_key_store_name: "Half-Life 2",
        config.json_key_store_buildid: "500",
        config.json_key_store_paths: ["saves", os.path.join("saves", "slot1")]})

    data = update_as(json_root, game_root)

    assert store["store"].asked == [("220", "beta")]
    assert data["store"][config.json_key_store_name] == "Half-Life 2"
    assert data["store"][config.json_key_store_buildid] == "500"
    assert data["store"][config.json_key_store_paths] == ["saves"]


def test_a_default_build_id_does_not_replace_a_known_one(json_root, game_root, store):
    write(json_path(json_root, CATEGORY, SUBCATEGORY), json.dumps({
        "store": {config.json_key_store_appid: "220", config.json_key_store_buildid: "500"}}))
    store["store"].latest = latest(**{config.json_key_store_buildid: config.default_buildid})

    data = update_as(json_root, game_root)

    assert data["store"][config.json_key_store_buildid] == "500"


def test_a_default_build_id_fills_an_empty_one(json_root, game_root, store):
    write(json_path(json_root, CATEGORY, SUBCATEGORY), json.dumps({
        "store": {config.json_key_store_appid: "220"}}))
    store["store"].latest = latest(**{config.json_key_store_buildid: config.default_buildid})

    data = update_as(json_root, game_root)

    assert data["store"][config.json_key_store_buildid] == config.default_buildid


def test_a_console_game_launches_its_best_file(json_root, game_root, no_store):
    write(game_root / "Game (USA).nes")
    nes = config.Subcategory.NINTENDO_NES

    data = update_as(json_root, game_root, category = config.Category.NINTENDO, subcategory = nes)

    assert data[config.json_key_launch_file] == "Game (USA).nes"


def test_a_console_game_without_files_has_no_launch_file(json_root, game_root, no_store):
    nes = config.Subcategory.NINTENDO_NES

    data = update_as(json_root, game_root, category = config.Category.NINTENDO, subcategory = nes)

    assert config.json_key_launch_file not in data


def test_dlc_content_is_listed_flat_without_a_store(json_root, game_root, monkeypatch):
    monkeypatch.setattr(
        jsondata.stores, "get_store_by_platform", lambda **kwargs: pytest.fail("dlc has no store data"))
    write(game_root / config.json_key_dlc / "content.bin")

    data = update_as(json_root, game_root, supercategory = config.Supercategory.DLC)

    assert data[config.json_key_files] == [os.path.join(config.json_key_dlc, "content.bin")]
    assert config.json_key_dlc not in data
    assert config.json_key_transform_file not in data


def test_a_json_directory_that_cannot_be_made_creates_nothing(json_root, monkeypatch):
    monkeypatch.setattr(jsondata.fileops, "make_directory", lambda **kwargs: False)

    assert jsondata.create_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME) is False
    assert not json_file(json_root).exists()


def test_an_unwritable_json_file_fails_the_update(json_root, game_root, no_store, monkeypatch):
    jsondata.create_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME)
    monkeypatch.setattr(jsondata.serialization, "write_json_file", lambda **kwargs: False)

    assert jsondata.update_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME, str(game_root)) is False


###########################################################
# Building json files
###########################################################

@pytest.fixture
def building(monkeypatch):
    state = {"created": [], "updated": [], "create_ok": True, "update_ok": True}

    def create_game_json_file(game_name, **kwargs):
        state["created"].append(game_name)
        return state["create_ok"]

    def update_game_json_file(game_name, game_root, locker_type, **kwargs):
        state["updated"].append((game_name, game_root, locker_type))
        return state["update_ok"]

    monkeypatch.setattr(jsondata, "create_game_json_file", create_game_json_file)
    monkeypatch.setattr(jsondata, "update_game_json_file", update_game_json_file)
    monkeypatch.setattr(jsondata.logger, "log_info", lambda message, **kwargs: None)
    return state


def test_building_creates_then_updates_from_the_game_root(building, game_root):
    assert jsondata.build_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME, game_root = str(game_root)) is True
    assert building["created"] == [GAME]
    assert building["updated"] == [(GAME, str(game_root), None)]


def test_building_defaults_to_the_locker_game_root(building, game_root, monkeypatch):
    monkeypatch.setattr(jsondata.environment, "get_locker_gaming_files_dir", lambda **kwargs: str(game_root))

    assert jsondata.build_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME) is True
    assert building["updated"][0][1] == str(game_root)


def test_building_without_a_game_root_does_nothing(building, tmp_path, monkeypatch):
    monkeypatch.setattr(jsondata.environment, "get_locker_gaming_files_dir", lambda **kwargs: str(tmp_path / "absent"))

    assert jsondata.build_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME) is False
    assert building["created"] == []


def test_a_failed_create_skips_the_update(building, game_root):
    building["create_ok"] = False

    assert jsondata.build_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME, game_root = str(game_root)) is False
    assert building["updated"] == []


def test_building_reports_the_update_result(building, game_root):
    building["update_ok"] = False

    assert jsondata.build_game_json_file(ROMS, CATEGORY, SUBCATEGORY, GAME, game_root = str(game_root)) is False


@pytest.fixture
def every_game(monkeypatch):
    state = {"built": [], "result": True, "lockers": []}

    def find_locker_game_names(game_supercategory, game_category, game_subcategory, locker_type):
        state["lockers"].append(locker_type)
        return ["%s/A" % game_subcategory, "%s/B" % game_subcategory]

    def build_game_json_file(game_name, **kwargs):
        state["built"].append(game_name)
        return state["result"]

    monkeypatch.setattr(jsondata.gameinfo, "find_locker_game_names", find_locker_game_names)
    monkeypatch.setattr(jsondata, "build_game_json_file", build_game_json_file)
    return state


def test_building_everything_visits_every_subcategory(every_game):
    assert jsondata.build_all_game_json_files() is True

    expected = sum(len(config.subcategory_map[category]) for category in config.Category.members()) * 2
    assert len(every_game["built"]) == expected


def test_building_can_be_limited_to_categories_and_subcategories(every_game):
    assert jsondata.build_all_game_json_files(
        locker_type = "Primary", categories = [str(CATEGORY)], subcategories = [str(SUBCATEGORY)]) is True
    assert every_game["built"] == ["%s/A" % SUBCATEGORY, "%s/B" % SUBCATEGORY]
    assert every_game["lockers"] == ["Primary"]


def test_building_everything_stops_at_a_failure(every_game):
    every_game["result"] = False

    assert jsondata.build_all_game_json_files() is False
    assert len(every_game["built"]) == 1
