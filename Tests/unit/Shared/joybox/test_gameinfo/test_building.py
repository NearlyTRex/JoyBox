# Imports
import pytest

# Local imports
from joybox import config, gameinfo


###########################################################
# A game built from its json file
#
# Everything downstream - launching, syncing, backups - reads a GameInfo, and
# it is built from the json file's location as much as its contents. A field
# that does not round trip is one that silently reverts on the next write.
###########################################################

GAME_NAME = "Half-Life 2"


@pytest.fixture
def game_tree(isolated_settings, tmp_path):
    # A json file where GameInfo expects one, so the categories parse.
    root = tmp_path / "metadata"
    isolated_settings.set_value("UserData.Dirs", "game_metadata_dir", str(root))
    game_dir = root / "Json" / "Roms" / "Computer" / "Steam" / GAME_NAME
    game_dir.mkdir(parents = True)
    return {"root": root, "dir": game_dir}


def write_game(game_tree, data = None, name = GAME_NAME):
    import json

    game_dir = game_tree["root"] / "Json" / "Roms" / "Computer" / "Steam" / name
    game_dir.mkdir(parents = True, exist_ok = True)
    json_file = game_dir / (name + ".json")
    with open(str(json_file), "w") as handle:
        json.dump(data if data is not None else {}, handle)
    return str(json_file)


@pytest.fixture
def game(game_tree):
    from joybox import gameinfo as gameinfo_module

    return gameinfo_module.GameInfo(
        json_file = write_game(game_tree, {"steam": {"appid": "220"}}))


###########################################################
# Building
###########################################################

def test_a_game_is_named_after_its_json_file(game):
    assert game.get_name() == GAME_NAME


def test_a_game_derives_its_categories_from_where_it_sits(game):
    assert game.get_supercategory() == config.Supercategory.ROMS
    assert game.get_category() == config.Category.COMPUTER
    assert game.get_subcategory() == config.Subcategory.COMPUTER_STEAM


def test_a_game_derives_its_platform(game):
    assert game.get_platform() == gameinfo.derive_game_platform_from_categories(
        config.Category.COMPUTER, config.Subcategory.COMPUTER_STEAM)


def test_a_game_remembers_the_file_it_came_from(game, game_tree):
    assert game.get_json_file() == str(
        game_tree["dir"] / (GAME_NAME + ".json"))


def test_a_game_reads_its_json_contents(game):
    assert game.get_store_appid("steam") == "220"


def test_a_game_without_a_json_file_cannot_be_built(game_tree, tmp_path):
    from joybox import gameinfo as gameinfo_module

    with pytest.raises(FileNotFoundError):
        gameinfo_module.GameInfo(json_file = str(tmp_path / "absent.json"))


def test_a_json_file_outside_the_collection_cannot_be_built(game_tree, tmp_path):
    # The categories come from the path, and without them nothing downstream
    # knows where the game belongs.
    from joybox import gameinfo as gameinfo_module

    stray = tmp_path / "stray.json"
    stray.write_text("{}")

    with pytest.raises(ValueError, match = "categories"):
        gameinfo_module.GameInfo(json_file = str(stray))


###########################################################
# Round tripping every store field
#
# These accessors are generated in pairs over the same store dictionary, so
# one whose getter and setter disagree on a key is invisible until something
# reads back what it just wrote.
###########################################################

def store_fields():
    from joybox import gameinfo as gameinfo_module

    # store_launch_programs wraps store_launch in Program objects rather than
    # storing a value of its own, so it is covered separately below.
    skipped = {"store_launch_programs"}

    fields = []
    for name in dir(gameinfo_module.GameInfo):
        if not name.startswith("set_store_"):
            continue
        field = name[len("set_"):]
        if field in skipped:
            continue
        if hasattr(gameinfo_module.GameInfo, "get_" + field):
            fields.append(field)
    return sorted(fields)


STORE_FIELDS = store_fields()


def test_the_store_fields_were_discovered():
    assert len(STORE_FIELDS) > 10


@pytest.mark.parametrize("field", STORE_FIELDS)
def test_every_store_field_reads_back_what_was_written(game, field):
    setter = getattr(game, "set_" + field)
    getter = getattr(game, "get_" + field)

    setter("round-trip-value", store_key = "steam")

    assert getter(store_key = "steam") == "round-trip-value"


@pytest.mark.parametrize("field", STORE_FIELDS)
def test_no_two_store_fields_share_a_key(game, field):
    # A copied accessor that kept the key it was copied from would make two
    # fields shadow each other.
    getattr(game, "set_" + field)("value-for-%s" % field, store_key = "steam")

    for other in STORE_FIELDS:
        if other == field:
            continue
        assert getattr(game, "get_" + other)(store_key = "steam") != \
            "value-for-%s" % field, "%s and %s share a key" % (field, other)


def test_launch_programs_are_stored_as_their_data(game):
    # The launch entries are Program objects in memory and plain data in the
    # json, and the pair has to agree on that crossing.
    from joybox import computer

    program = computer.Program({"name": "hl2.exe", "args": ["-novid"]})
    game.set_store_launch_programs([program], store_key = "steam")

    assert game.get_store_launch(store_key = "steam") == [program.get_data()]


def test_launch_programs_are_read_back_as_programs(game):
    from joybox import computer

    program = computer.Program({"name": "hl2.exe"})
    game.set_store_launch_programs([program], store_key = "steam")

    restored = game.get_store_launch_programs(store_key = "steam")

    assert len(restored) == 1
    assert isinstance(restored[0], computer.Program)
    assert restored[0].get_data() == program.get_data()


def test_a_store_field_is_kept_per_store(game):
    # A game can be owned on more than one store, and the ids are different.
    game.set_store_appid("220", store_key = "steam")
    game.set_store_appid("gog-1207659235", store_key = "gog")

    assert game.get_store_appid(store_key = "steam") == "220"
    assert game.get_store_appid(store_key = "gog") == "gog-1207659235"


def test_a_store_the_game_did_not_have_yet_is_added(game):
    # A game bought on a second store has no entry until something writes
    # one, and that write has to land rather than disappear.
    game.set_store_appid("gog-1207659235", store_key = "gog")

    assert game.get_store_appid(store_key = "gog") == "gog-1207659235"


def test_an_unset_store_field_reads_as_nothing(game):
    assert not game.get_store_buildid(store_key = "steam")
