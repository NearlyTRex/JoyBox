# Imports
import json

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import amazon
from amazon_helpers import APPID, NILE, PYTHON


@pytest.fixture
def no_manifest(monkeypatch):
    class EmptyManifest:
        def find_entry_by_name(self, **kwargs):
            return None
    monkeypatch.setattr(amazon.storebase.manifest, "get_manifest_instance", lambda: EmptyManifest())


def details(amazon_store, recording_command, output):
    recording_command.output = output if isinstance(output, str) else json.dumps(output)
    return amazon_store.get_latest_jsondata(APPID)


###########################################################
# Details
###########################################################

def test_details_become_jsondata(amazon_store, tools, recording_command, no_manifest):
    data = details(amazon_store, recording_command, {"version": " 1.2.3 ", "product": {"title": " Tomb Raider "}})

    assert recording_command.only() == [PYTHON, NILE, "--quiet", "details", APPID]
    assert data.get_value(config.json_key_store_appid) == APPID
    assert data.get_value(config.json_key_store_buildid) == "1.2.3"
    assert data.get_value(config.json_key_store_name) == "Tomb Raider"
    assert data.get_value(config.json_key_store_paths) == []
    assert data.get_value(config.json_key_store_keys) == []


def test_missing_details_fall_back_to_defaults(amazon_store, tools, recording_command, no_manifest):
    data = details(amazon_store, recording_command, {})

    assert data.get_value(config.json_key_store_buildid) == config.default_buildid
    assert data.get_value(config.json_key_store_name) == ""


@pytest.mark.parametrize("payload", [
    {"version": None, "product": None},
    {"version": 7, "product": {"title": None}},
    {"version": "  ", "product": "Tomb Raider"},
])
def test_null_or_odd_details_fall_back_to_defaults(amazon_store, tools, recording_command, no_manifest, payload):
    data = details(amazon_store, recording_command, payload)

    assert data.get_value(config.json_key_store_buildid) == config.default_buildid
    assert data.get_value(config.json_key_store_name) == ""


@pytest.mark.parametrize("output", ["not json", "null", "[1, 2]", '"text"'])
def test_output_that_is_not_an_object_is_refused(amazon_store, tools, recording_command, output):
    assert details(amazon_store, recording_command, output) is None


def test_details_need_output_tools_and_an_id(amazon_store, tools, recording_command):
    assert details(amazon_store, recording_command, "") is None
    assert amazon_store.get_latest_jsondata("") is None
    assert amazon_store.get_latest_jsondata(None) is None
    assert len(recording_command.calls) == 1


@pytest.mark.parametrize("tool", ["PythonVenvPython", "Nile"])
def test_details_need_python_and_nile(amazon_store, tools, recording_command, tool):
    del tools[tool]

    assert amazon_store.get_latest_jsondata(APPID) is None
    assert recording_command.calls == []


def test_manifest_paths_join_the_details(amazon_store, tools, recording_command, monkeypatch):
    class Entry:
        def get_paths(self, base_path):
            return [base_path + "/saves", "STORE_INSTALL_DIR/cache"]
        def get_keys(self):
            return ["HKEY_CURRENT_USER/Software/Tomb Raider"]

    class OneEntryManifest:
        def find_entry_by_name(self, name, **kwargs):
            return Entry() if name == APPID else None

    monkeypatch.setattr(amazon.storebase.manifest, "get_manifest_instance", lambda: OneEntryManifest())
    data = details(amazon_store, recording_command, {"product": {"title": "Tomb Raider"}})

    assert data.get_value(config.json_key_store_paths) == [config.token_game_install_dir + "/saves"]
    assert data.get_value(config.json_key_store_keys) == ["HKEY_CURRENT_USER/Software/Tomb Raider"]
