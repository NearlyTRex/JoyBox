# Imports
import json

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import epic
from epic_helpers import LEGENDARY, legendary_info


###########################################################
# Game info
###########################################################

def info(epic_store, recording_command, output, identifier = "Sugar"):
    recording_command.output = output
    return epic_store.get_latest_jsondata(identifier)


def test_game_info_is_read_from_legendary(epic_store, tools, recording_command, no_manifest):
    data = info(epic_store, recording_command, legendary_info(title = " Hades ", version = " 1.38290 "))

    assert recording_command.only() == LEGENDARY + ["info", "Sugar", "--json"]
    assert data.get_value(config.json_key_store_appname) == "Sugar"
    assert data.get_value(config.json_key_store_name) == "Hades"
    assert data.get_value(config.json_key_store_buildid) == "1.38290"
    assert data.get_value(config.json_key_store_paths) == []


def test_the_version_is_the_build_id(epic_store, tools, recording_command, no_manifest):
    recording_command.output = legendary_info(title = "Hades", version = "1.38290")

    assert epic_store.get_latest_version("Sugar") == "1.38290"


@pytest.mark.parametrize("game", [{"title": "Hades"}, {"title": "Hades", "version": None}])
def test_a_game_without_a_version_gets_the_default_build(epic_store, tools, recording_command, no_manifest, game):
    # Legendary reports a null version when the game has no build for the platform
    data = info(epic_store, recording_command, legendary_info(**game))

    assert data.get_value(config.json_key_store_buildid) == config.default_buildid


def test_a_null_title_gives_an_empty_name(epic_store, tools, recording_command, no_manifest):
    data = info(epic_store, recording_command, legendary_info(title = None, version = "1"))

    assert data.get_value(config.json_key_store_name) == ""


def test_the_cloud_save_folder_becomes_a_tokenized_path(epic_store, tools, recording_command, no_manifest):
    output = legendary_info(title = "Hades", version = "1", cloud_save_folder = " {AppData}/../Roaming/Hades/{InstallDir}/Saves ")

    data = info(epic_store, recording_command, output)

    assert data.get_value(config.json_key_store_paths) == [
        config.token_user_profile_dir + "/AppData/Roaming/Hades/" + config.token_game_install_dir + "/Saves"]


def test_a_cloud_save_folder_under_the_user_id_is_dropped(epic_store, tools, recording_command, no_manifest):
    output = legendary_info(title = "Hades", version = "1", cloud_save_folder = "{AppData}/Hades/{EpicId}")

    assert info(epic_store, recording_command, output).get_value(config.json_key_store_paths) == []


def test_manifest_paths_join_the_game_info(epic_store, tools, recording_command, monkeypatch):
    class Entry:
        def get_paths(self, base_path):
            return [base_path + "/Saves"]
        def get_keys(self):
            return ["HKEY_CURRENT_USER/Software/Supergiant"]

    class OneEntryManifest:
        def find_entry_by_name(self, name, **kwargs):
            return Entry() if name == "Sugar" else None

    monkeypatch.setattr(epic.storebase.manifest, "get_manifest_instance", lambda: OneEntryManifest())
    data = info(epic_store, recording_command, legendary_info(title = "Hades", version = "1"))

    assert data.get_value(config.json_key_store_paths) == [config.token_game_install_dir + "/Saves"]
    assert data.get_value(config.json_key_store_keys) == ["HKEY_CURRENT_USER/Software/Supergiant"]


@pytest.mark.parametrize("output", [
    "",
    "[cli] ERROR: No game information available\n",
    "not json",
    json.dumps(["Sugar"]),
    json.dumps({"install": {}}),
])
def test_unusable_info_gives_no_jsondata(epic_store, tools, recording_command, no_manifest, output):
    assert info(epic_store, recording_command, output) is None


def test_an_invalid_identifier_runs_nothing(epic_store, tools, recording_command):
    assert epic_store.get_latest_jsondata("") is None
    assert epic_store.get_latest_version("") is None
    assert recording_command.calls == []


@pytest.mark.parametrize("tool", ["PythonVenvPython", "Legendary"])
def test_info_needs_python_and_legendary(epic_store, tools, recording_command, tool):
    del tools[tool]

    assert epic_store.get_latest_jsondata("Sugar") is None
    assert recording_command.calls == []
