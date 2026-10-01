# Imports
import json

# Third-party imports
import pytest

# Local imports
from joybox import config
from legacy_helpers import HEIRLOOM, heirloom_game, heirloom_list


def summary(purchases):
    return [(
        purchase.get_value(config.json_key_store_appid),
        purchase.get_value(config.json_key_store_name)) for purchase in purchases]


###########################################################
# Purchases
###########################################################

def test_each_listed_game_becomes_a_purchase(legacy_store, tools, recording_command):
    recording_command.output = heirloom_list(
        heirloom_game(" uuid-1 ", " Mystery Case Files "),
        heirloom_game("uuid-2", "Hidden Expedition"))

    purchases = legacy_store.get_latest_purchases()

    assert recording_command.only() == HEIRLOOM + ["list", "--json", "--quiet"]
    assert summary(purchases) == [("uuid-1", "Mystery Case Files"), ("uuid-2", "Hidden Expedition")]
    assert all(purchase.get_platform() == config.Platform.COMPUTER_LEGACY_GAMES for purchase in purchases)


def test_an_empty_library_gives_no_purchases(legacy_store, tools, recording_command):
    recording_command.output = heirloom_list()

    assert legacy_store.get_latest_purchases() == []


@pytest.mark.parametrize("name", [None, 7, "missing"])
def test_a_game_without_a_usable_name_gets_an_empty_name(legacy_store, tools, recording_command, name):
    game = {"installer_uuid": "uuid-1"}
    if name != "missing":
        game["game_name"] = name
    recording_command.output = heirloom_list(game)

    assert summary(legacy_store.get_latest_purchases()) == [("uuid-1", "")]


@pytest.mark.parametrize("entry", [
    {"game_name": "No Id"},
    {"installer_uuid": None, "game_name": "Null Id"},
    {"installer_uuid": "  ", "game_name": "Blank Id"},
    "uuid-3",
    None,
    ["uuid-4"],
])
def test_entries_without_an_installer_id_are_skipped(legacy_store, tools, recording_command, entry):
    recording_command.output = json.dumps([entry, heirloom_game("uuid-1", "Kept")])

    assert summary(legacy_store.get_latest_purchases()) == [("uuid-1", "Kept")]


@pytest.mark.parametrize("output", ["", None])
def test_no_output_gives_no_purchases(legacy_store, tools, recording_command, output):
    recording_command.output = output

    assert legacy_store.get_latest_purchases() is None


@pytest.mark.parametrize("output", ["not json", "{\"installer_uuid\": \"uuid-1\"}", "null", "42", "\"text\""])
def test_output_that_is_not_a_json_list_gives_no_purchases(legacy_store, tools, recording_command, output):
    recording_command.output = output

    assert legacy_store.get_latest_purchases() is None


@pytest.mark.parametrize("tool", ["PythonVenvPython", "Heirloom"])
def test_purchases_need_python_and_heirloom(legacy_store, tools, recording_command, tool):
    del tools[tool]

    assert legacy_store.get_latest_purchases() is None
    assert recording_command.calls == []


def test_purchases_pass_their_run_flags_through(legacy_store, tools, recording_command):
    recording_command.output = heirloom_list()

    legacy_store.get_latest_purchases(verbose = True, exit_on_failure = True)

    assert recording_command.calls[0]["kwargs"] == {"verbose": True, "exit_on_failure": True}
