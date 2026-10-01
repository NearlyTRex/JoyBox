# Imports
import json

# Third-party imports
import pytest

# Local imports
from joybox import config
from legacy_helpers import HEIRLOOM


def info(legacy_store, recording_command, output, identifier = "uuid-1"):
    recording_command.output = output
    return legacy_store.get_latest_jsondata(identifier)


###########################################################
# Game info
###########################################################

def test_game_info_is_read_from_heirloom(legacy_store, tools, recording_command, no_manifest):
    data = info(legacy_store, recording_command, json.dumps({"game_name": " Mystery Case Files "}))

    assert recording_command.only() == HEIRLOOM + ["info", "--uuid", "uuid-1", "--quiet"]
    assert data.get_value(config.json_key_store_appid) == "uuid-1"
    assert data.get_value(config.json_key_store_name) == "Mystery Case Files"
    assert data.get_value(config.json_key_store_buildid) == config.default_buildid
    assert data.get_value(config.json_key_store_paths) == []
    assert data.get_value(config.json_key_store_keys) == []


def test_the_version_is_the_default_build(legacy_store, tools, recording_command, no_manifest):
    recording_command.output = json.dumps({"game_name": "Mystery Case Files"})

    assert legacy_store.get_latest_version("uuid-1") == config.default_buildid


@pytest.mark.parametrize("game", [{}, {"game_name": None}, {"game_name": 3}])
def test_a_game_without_a_usable_name_gets_an_empty_name(legacy_store, tools, recording_command, no_manifest, game):
    data = info(legacy_store, recording_command, json.dumps(game))

    assert data.get_value(config.json_key_store_name) == ""


def test_save_paths_come_from_the_manifest(legacy_store, tools, recording_command, monkeypatch):
    from joybox.stores import legacy

    class Entry:
        def get_paths(self, base_path):
            return [base_path + "/Saves"]

        def get_keys(self):
            return ["HKCU/Legacy"]

    class Manifest:
        def find_entry_by_name(self, name, **kwargs):
            return Entry() if name == "uuid-1" else None

    monkeypatch.setattr(legacy.storebase.manifest, "get_manifest_instance", lambda: Manifest())

    data = info(legacy_store, recording_command, json.dumps({"game_name": "Mystery Case Files"}))

    assert data.get_value(config.json_key_store_paths) == [config.token_game_install_dir + "/Saves"]
    assert data.get_value(config.json_key_store_keys) == ["HKCU/Legacy"]


@pytest.mark.parametrize("output", ["", None, "No game information available for uuid-1"])
def test_missing_info_gives_nothing(legacy_store, tools, recording_command, output):
    assert info(legacy_store, recording_command, output) is None


@pytest.mark.parametrize("output", ["not json", "[]", "null", "\"text\"", "[{\"game_name\": \"Listed\"}]"])
def test_info_that_is_not_a_json_object_gives_nothing(legacy_store, tools, recording_command, output):
    assert info(legacy_store, recording_command, output) is None


@pytest.mark.parametrize("identifier", ["", None, 5])
def test_an_invalid_identifier_runs_nothing(legacy_store, tools, recording_command, identifier):
    assert legacy_store.get_latest_jsondata(identifier) is None
    assert recording_command.calls == []


@pytest.mark.parametrize("tool", ["PythonVenvPython", "Heirloom"])
def test_info_needs_python_and_heirloom(legacy_store, tools, recording_command, tool):
    del tools[tool]

    assert legacy_store.get_latest_jsondata("uuid-1") is None
    assert recording_command.calls == []
