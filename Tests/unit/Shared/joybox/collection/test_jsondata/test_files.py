# Imports
import json
import os
import pytest

# Local imports
from joybox import config
from joybox.collection import jsondata


###########################################################
# Game json data
#
# The collection's per game json files, and the ignore list that keeps rejected
# import suggestions from coming back on every scan.
###########################################################

ROMS = config.Supercategory.ROMS
CATEGORY = config.Category.NINTENDO
SUBCATEGORY = config.Subcategory.NINTENDO_NES


@pytest.fixture
def metadata_root(monkeypatch, tmp_path):
    root = tmp_path / "metadata"
    root.mkdir()
    monkeypatch.setattr(
        jsondata.environment, "get_game_json_metadata_root_dir", lambda: str(root))
    return root


def ignore_file():
    return jsondata.environment.get_game_json_metadata_ignore_file(
        ROMS, CATEGORY, SUBCATEGORY)


def read_ignores():
    with open(ignore_file()) as handle:
        return json.load(handle)


def get_ignores():
    return jsondata.get_game_json_ignore_entries(ROMS, CATEGORY, SUBCATEGORY)


def add_ignore(identifier, name):
    return jsondata.add_game_json_ignore_entry(
        ROMS, CATEGORY, SUBCATEGORY, identifier, name)


def write_game(name, data):
    target = jsondata.environment.get_game_json_metadata_file(
        ROMS, CATEGORY, SUBCATEGORY, name)
    os.makedirs(os.path.dirname(target), exist_ok = True)
    with open(target, "w") as handle:
        handle.write(json.dumps(data))
    return target


###########################################################
# Eligible categories
###########################################################

@pytest.mark.parametrize("supercategory", [
    config.Supercategory.ROMS,
    config.Supercategory.DLC,
    config.Supercategory.UPDATES,
])
def test_json_files_are_possible_for_game_content(supercategory):
    assert jsondata.are_game_json_file_possible(supercategory) is True


@pytest.mark.parametrize("supercategory", [
    entry for entry in config.Supercategory.members()
    if entry not in (config.Supercategory.ROMS,
                     config.Supercategory.DLC,
                     config.Supercategory.UPDATES)
])
def test_json_files_are_not_possible_elsewhere(supercategory):
    # Saves and setup files carry no game json.
    assert jsondata.are_game_json_file_possible(supercategory) is False


def test_the_category_check_ignores_the_lower_levels():
    assert jsondata.are_game_json_file_possible(
        config.Supercategory.ROMS, "not-a-category", "not-a-subcategory") is True


###########################################################
# Reading game json
###########################################################

def test_a_missing_game_reads_as_nothing(metadata_root):
    assert jsondata.read_game_json_data(ROMS, CATEGORY, SUBCATEGORY, "Absent") is None


def test_an_ineligible_supercategory_reads_as_nothing(metadata_root):
    write_game("Chrono Trigger (USA)", {"appname": "Chrono Trigger"})

    assert jsondata.read_game_json_data(
        config.Supercategory.SAVES, CATEGORY, SUBCATEGORY, "Chrono Trigger (USA)") is None


def test_a_game_json_is_read(metadata_root):
    write_game("Chrono Trigger (USA)", {"appname": "Chrono Trigger"})
    data = jsondata.read_game_json_data(ROMS, CATEGORY, SUBCATEGORY, "Chrono Trigger (USA)")

    assert data is not None
    assert data.get_value("appname") == "Chrono Trigger"


def test_a_read_game_json_carries_its_platform(metadata_root):
    # The platform decides which of a value's platform variants is returned.
    write_game("Chrono Trigger (USA)", {})
    data = jsondata.read_game_json_data(ROMS, CATEGORY, SUBCATEGORY, "Chrono Trigger (USA)")

    assert data.get_platform() is not None


def test_an_empty_game_json_reads_as_an_empty_object(metadata_root):
    write_game("Chrono Trigger (USA)", {})
    data = jsondata.read_game_json_data(ROMS, CATEGORY, SUBCATEGORY, "Chrono Trigger (USA)")

    assert data is not None
    assert data.get_data() == {}


###########################################################
# Ignore entries
###########################################################

def test_an_empty_ignore_list_reads_as_empty(metadata_root):
    assert get_ignores() == {}


def test_reading_the_ignore_list_creates_it(metadata_root):
    get_ignores()

    assert os.path.exists(ignore_file())


def test_an_ignore_entry_is_added(metadata_root):
    assert add_ignore("12345", "Chrono Trigger") is True
    assert get_ignores() == {"12345": "Chrono Trigger"}


def test_an_ignore_entry_reaches_the_file(metadata_root):
    add_ignore("12345", "Chrono Trigger")

    assert read_ignores() == {"12345": "Chrono Trigger"}


def test_several_ignore_entries_accumulate(metadata_root):
    # Each rejection has to stick; rewriting the file from scratch would
    # resurrect every earlier suggestion on the next scan.
    add_ignore("12345", "Chrono Trigger")
    add_ignore("67890", "Super Metroid")

    assert get_ignores() == {"12345": "Chrono Trigger", "67890": "Super Metroid"}


def test_re_adding_an_identifier_replaces_its_name(metadata_root):
    add_ignore("12345", "Chrono Trigger")
    add_ignore("12345", "Chrono Trigger (USA)")

    assert get_ignores() == {"12345": "Chrono Trigger (USA)"}


def test_ignore_entries_are_written_sorted(metadata_root):
    add_ignore("67890", "Super Metroid")
    add_ignore("12345", "Chrono Trigger")

    assert list(read_ignores()) == ["12345", "67890"]


def test_an_ignore_entry_with_an_empty_name_is_dropped(metadata_root):
    # The file is cleaned of empty values, so a blank name is not a rejection.
    add_ignore("12345", "Chrono Trigger")
    add_ignore("67890", "")

    assert get_ignores() == {"12345": "Chrono Trigger"}


def test_an_identifier_with_punctuation_round_trips(metadata_root):
    add_ignore("steam:12345", "Chrono Trigger")

    assert get_ignores() == {"steam:12345": "Chrono Trigger"}


def test_a_game_name_with_punctuation_round_trips(metadata_root):
    add_ignore("12345", "Final Fantasy VI (USA) (Rev 1)")

    assert get_ignores() == {"12345": "Final Fantasy VI (USA) (Rev 1)"}


def test_an_ineligible_supercategory_has_no_ignore_entries(metadata_root):
    assert jsondata.get_game_json_ignore_entries(
        config.Supercategory.SAVES, CATEGORY, SUBCATEGORY) == {}


def test_an_ineligible_supercategory_accepts_no_ignore_entry(metadata_root):
    assert jsondata.add_game_json_ignore_entry(
        config.Supercategory.SAVES, CATEGORY, SUBCATEGORY, "12345", "Game") is True
    assert not os.path.exists(str(metadata_root / str(config.Supercategory.SAVES)))


def test_ignore_lists_are_kept_per_subcategory(metadata_root):
    # A rejection for one console must not hide a suggestion on another.
    add_ignore("12345", "Chrono Trigger")
    other = jsondata.get_game_json_ignore_entries(
        ROMS, CATEGORY, config.Subcategory.NINTENDO_SNES)

    assert other == {}
    assert get_ignores() == {"12345": "Chrono Trigger"}


def test_ignore_lists_are_kept_per_supercategory(metadata_root):
    add_ignore("12345", "Chrono Trigger")
    other = jsondata.get_game_json_ignore_entries(
        config.Supercategory.DLC, CATEGORY, SUBCATEGORY)

    assert other == {}
