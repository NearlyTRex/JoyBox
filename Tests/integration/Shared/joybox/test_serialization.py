# Imports
import json
import os

# Third-party imports
import pytest

# Local imports
from joybox import serialization


def write_json(path, data):
    with open(path, "w") as handle:
        handle.write(json.dumps(data))
    return path


def read_json(path):
    with open(path) as handle:
        return json.load(handle)


###########################################################
# Reading
###########################################################

def test_a_json_file_is_read(tmp_path):
    target = write_json(str(tmp_path / "game.json"), {"name": "Chrono Trigger"})
    assert serialization.read_json_file(target) == {"name": "Chrono Trigger"}


def test_a_non_json_extension_is_refused(tmp_path):
    # The extension is the guard against reading an arbitrary file as metadata.
    target = str(tmp_path / "game.txt")
    with open(target, "w") as handle:
        handle.write('{"name": "x"}')

    assert serialization.read_json_file(target) == {}


def test_a_missing_file_reads_as_empty(tmp_path):
    assert serialization.read_json_file(str(tmp_path / "absent.json")) == {}


def test_malformed_json_reads_as_empty(tmp_path):
    target = str(tmp_path / "broken.json")
    with open(target, "w") as handle:
        handle.write("{not valid json")

    assert serialization.read_json_file(target) == {}


def test_a_json_string_is_parsed():
    assert serialization.parse_json_string('{"a": 1}') == {"a": 1}


def test_a_malformed_json_string_parses_as_empty():
    assert serialization.parse_json_string("{nope") == {}


###########################################################
# Writing
###########################################################

def test_a_json_file_is_written(tmp_path):
    target = str(tmp_path / "game.json")

    assert serialization.write_json_file(target, {"name": "Chrono Trigger"}) is True
    assert read_json(target) == {"name": "Chrono Trigger"}


def test_writing_creates_missing_parent_directories(tmp_path):
    target = str(tmp_path / "deep" / "nested" / "game.json")

    assert serialization.write_json_file(target, {"a": 1}) is True
    assert os.path.isfile(target)


def test_writing_a_non_json_extension_is_refused(tmp_path):
    target = str(tmp_path / "game.txt")

    assert serialization.write_json_file(target, {"a": 1}) is False
    assert not os.path.exists(target)


def test_keys_are_sorted_on_request(tmp_path):
    target = str(tmp_path / "game.json")
    serialization.write_json_file(target, {"c": 1, "a": 2, "b": 3}, sort_keys = True)

    with open(target) as handle:
        contents = handle.read()
    assert contents.index('"a"') < contents.index('"b"') < contents.index('"c"')


def test_a_written_file_round_trips(tmp_path):
    target = str(tmp_path / "game.json")
    data = {"name": "Game", "tags": ["a", "b"], "meta": {"year": 1995}}

    serialization.write_json_file(target, data)

    assert serialization.read_json_file(target) == data


def test_pretend_run_does_not_write(tmp_path):
    target = str(tmp_path / "game.json")

    assert serialization.write_json_file(target, {"a": 1}, pretend_run = True) is True
    assert not os.path.exists(target)


###########################################################
# Cleaning
###########################################################

def test_empty_values_are_removed(tmp_path):
    target = write_json(str(tmp_path / "game.json"), {
        "keep": "value",
        "empty_string": "",
        "null": None,
        "empty_list": [],
        "empty_dict": {},
        "false_flag": False,
    })

    assert serialization.clean_json_file(target, remove_empty_values = True) is True
    assert read_json(target) == {"keep": "value"}


def test_populated_values_survive_cleaning(tmp_path):
    data = {"name": "Game", "tags": ["a"], "meta": {"year": 1995}, "flag": True, "count": 0}
    target = write_json(str(tmp_path / "game.json"), data)

    serialization.clean_json_file(target, remove_empty_values = True)

    # A zero count is data, not an empty value.
    assert read_json(target) == data


def test_cleaning_can_sort_without_removing(tmp_path):
    # remove_empty_values was accepted but never read, so cleaning always stripped.
    data = {"c": "value", "a": "", "b": None}
    target = write_json(str(tmp_path / "game.json"), data)

    serialization.clean_json_file(target, sort_keys = True, remove_empty_values = False)

    assert read_json(target) == data


def test_cleaning_a_non_json_extension_is_refused(tmp_path):
    target = str(tmp_path / "game.txt")
    with open(target, "w") as handle:
        handle.write('{"a": ""}')

    assert serialization.clean_json_file(target) is False


def test_pretend_run_does_not_clean(tmp_path):
    data = {"keep": "value", "empty": ""}
    target = write_json(str(tmp_path / "game.json"), data)

    serialization.clean_json_file(target, remove_empty_values = True, pretend_run = True)

    assert read_json(target) == data


###########################################################
# Searching
###########################################################

@pytest.fixture
def collection(tmp_path):
    # Shaped like the real metadata: a store key holding a nested dict.
    write_json(str(tmp_path / "alpha.json"), {
        "zoom": {"appname": "killing_time", "name": "Killing Time"},
        "launch_file": "KT.EXE",
    })
    write_json(str(tmp_path / "beta.json"), {
        "puppetcombo": {"appname": "murder_house", "name": "Murder House"},
        "launch_file": "MH.EXE",
    })
    write_json(str(tmp_path / "gamma.json"), {
        "meta": {"nested": {"deep": "buried treasure"}},
        "name": "Gamma",
    })
    return str(tmp_path)


def test_a_top_level_value_is_found(collection):
    found = serialization.search_json_files(collection, search_values = ["Gamma"])

    assert len(found) == 1
    assert found[0].endswith("gamma.json")


def test_a_nested_value_is_found(collection):
    found = serialization.search_json_files(collection, search_values = ["Murder House"])

    assert len(found) == 1
    assert found[0].endswith("beta.json")


def test_a_value_after_a_nested_dictionary_is_found(collection):
    # gamma.json holds "meta" before "name"; the search must not stop at "meta".
    found = serialization.search_json_files(collection, search_values = ["Gamma"])

    assert [os.path.basename(path) for path in found] == ["gamma.json"]


def test_a_deeply_nested_value_is_found(collection):
    found = serialization.search_json_files(collection, search_values = ["buried treasure"])

    assert len(found) == 1


def test_search_keys_restrict_the_match(collection):
    assert serialization.search_json_files(
        collection, search_values = ["Killing Time"], search_keys = ["name"])
    assert not serialization.search_json_files(
        collection, search_values = ["Killing Time"], search_keys = ["appname"])


def test_a_partial_value_matches(collection):
    assert len(serialization.search_json_files(collection, search_values = ["Killing"])) == 1


def test_no_match_returns_nothing(collection):
    assert serialization.search_json_files(collection, search_values = ["nonexistent"]) == []


def test_an_empty_search_value_is_ignored(collection):
    assert serialization.search_json_files(collection, search_values = ["", None]) == []


def test_several_values_accumulate_matches(collection):
    found = serialization.search_json_files(
        collection, search_values = ["Killing Time", "Murder House"])

    assert len(found) == 2
