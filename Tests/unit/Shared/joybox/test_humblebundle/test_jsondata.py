# Imports
import json

# Third-party imports
import pytest

# Local imports
from joybox import config
from humble_helpers import MANAGER_CMD, download, game, show_cmd

APPNAME = "tombraider_windows"


def details(humble_store, recording_command, output):
    recording_command.output = output if isinstance(output, str) else json.dumps(output)
    return humble_store.get_latest_jsondata(APPNAME)


###########################################################
# Details
###########################################################

def test_details_become_jsondata(humble_store, tools, recording_command, no_manifest):
    data = details(humble_store, recording_command, game(" Tomb Raider ", download("windows", 1700000000)))

    assert recording_command.only() == show_cmd(APPNAME)
    assert data.get_platform() == config.Platform.COMPUTER_HUMBLE_BUNDLE
    assert data.get_value(config.json_key_store_appname) == APPNAME
    assert data.get_value(config.json_key_store_appid)
    assert data.get_value(config.json_key_store_name) == "Tomb Raider"
    assert data.get_value(config.json_key_store_buildid) == "1700000000"
    assert data.get_value(config.json_key_store_paths) == []
    assert data.get_value(config.json_key_store_keys) == []


def test_every_lookup_gets_a_fresh_appid(humble_store, tools, recording_command, no_manifest):
    first = details(humble_store, recording_command, game("Tomb Raider"))
    second = details(humble_store, recording_command, game("Tomb Raider"))

    assert first.get_value(config.json_key_store_appid) != second.get_value(config.json_key_store_appid)


def test_the_buildid_follows_the_preferred_platform_only(humble_store, tools, recording_command, no_manifest):
    data = details(humble_store, recording_command, game(
        "Tomb Raider", download("linux", 999), download("windows", 100, "200"), download("mac", 555)))

    assert data.get_value(config.json_key_store_buildid) == "200"


def test_a_game_without_preferred_downloads_keeps_the_default_buildid(humble_store, tools, recording_command, no_manifest):
    data = details(humble_store, recording_command, game("Tomb Raider", download("linux", 999)))

    assert data.get_value(config.json_key_store_buildid) == config.default_buildid


def test_missing_details_fall_back_to_defaults(humble_store, tools, recording_command, no_manifest):
    data = details(humble_store, recording_command, {})

    assert data.get_value(config.json_key_store_name) == ""
    assert data.get_value(config.json_key_store_buildid) == config.default_buildid


@pytest.mark.parametrize("payload", [
    {"human_name": None, "downloads": None},
    {"human_name": 7, "downloads": "windows"},
    {"downloads": [None, "windows", {"platform": "windows", "download_struct": None}]},
    {"downloads": [{"platform": "windows", "download_struct": [None, {}, {"timestamp": None}]}]},
    {"downloads": [{"platform": "windows", "download_struct": [{"timestamp": True}, {"timestamp": "  "}, {"timestamp": [1]}]}]},
])
def test_null_or_odd_details_fall_back_to_defaults(humble_store, tools, recording_command, no_manifest, payload):
    data = details(humble_store, recording_command, payload)

    assert data.get_value(config.json_key_store_name) == ""
    assert data.get_value(config.json_key_store_buildid) == config.default_buildid


def test_an_odd_build_entry_does_not_hide_a_good_one(humble_store, tools, recording_command, no_manifest):
    data = details(humble_store, recording_command, game(
        "Tomb Raider", {"platform": "windows", "download_struct": [{"timestamp": 300}, {"timestamp": None}]}))

    assert data.get_value(config.json_key_store_buildid) == "300"


@pytest.mark.parametrize("output", ["", None, "not json", "null", "[1, 2]", '"text"'])
def test_unreadable_details_are_no_jsondata(humble_store, tools, recording_command, no_manifest, output):
    recording_command.output = output

    assert humble_store.get_latest_jsondata(APPNAME) is None


@pytest.mark.parametrize("identifier", ["", None])
def test_an_invalid_identifier_is_not_looked_up(humble_store, tools, recording_command, identifier):
    assert humble_store.get_latest_jsondata(identifier) is None
    assert recording_command.calls == []


@pytest.mark.parametrize("tool", ["PythonVenvPython", "HumbleBundleManager"])
def test_details_need_python_and_the_manager(humble_store, tools, recording_command, tool):
    del tools[tool]

    assert humble_store.get_latest_jsondata(APPNAME) is None
    assert recording_command.calls == []


def test_details_pass_their_flags_through(humble_store, tools, recording_command, no_manifest):
    details(humble_store, recording_command, game("Tomb Raider"))
    humble_store.get_latest_jsondata(APPNAME, verbose = True, pretend_run = True, exit_on_failure = True)

    assert recording_command.calls[1]["kwargs"] == {"verbose": True, "pretend_run": True, "exit_on_failure": True}


def test_the_latest_version_is_the_buildid(humble_store, tools, recording_command, no_manifest):
    recording_command.output = json.dumps(game("Tomb Raider", download("windows", 42)))

    assert humble_store.get_latest_version(APPNAME) == "42"


def test_the_manager_is_authenticated(humble_store, tools, recording_command, no_manifest):
    details(humble_store, recording_command, game("Tomb Raider"))

    assert recording_command.only()[:len(MANAGER_CMD)] == MANAGER_CMD
