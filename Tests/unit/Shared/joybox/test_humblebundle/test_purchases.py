# Imports
import json
import os
import time

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import humblebundle
from humble_helpers import MANAGER_CMD, ManagerOutput, game, show_cmd

GREEN = "\x1b[32m"
CLEAR = "\x1b[0m"

GAMES = {
    "deponia_windows": game("Deponia"),
    "tombraider_windows": game("Tomb Raider")}


@pytest.fixture
def manager(humble_store, tools, recording_command, monkeypatch, tmp_path):
    output = ManagerOutput("deponia_windows\ntombraider_windows\n", dict(GAMES))

    def run_output_command(cmd, **kwargs):
        recording_command.calls.append({"cmd": list(cmd), "kwargs": kwargs})
        return output(cmd)
    monkeypatch.setattr(humblebundle.command, "run_output_command", run_output_command)
    monkeypatch.setattr(humble_store, "get_purchases_cache_dir", lambda: str(tmp_path / "cache"))
    output.cache = tmp_path / "cache" / "humble_purchases_cache.json"
    return output


def appnames(purchases):
    return [purchase.get_value(config.json_key_store_appname) for purchase in purchases]


def names(purchases):
    return [purchase.get_value(config.json_key_store_name) for purchase in purchases]


def commands(recording_command):
    return [call["cmd"] for call in recording_command.calls]


###########################################################
# Fetching
###########################################################

def test_the_library_becomes_purchases(humble_store, manager):
    purchases = humble_store.get_latest_purchases()

    assert appnames(purchases) == ["deponia_windows", "tombraider_windows"]
    assert names(purchases) == ["Deponia", "Tomb Raider"]
    assert all(purchase.get_platform() == config.Platform.COMPUTER_HUMBLE_BUNDLE for purchase in purchases)


def test_each_purchase_gets_its_own_appid(humble_store, manager):
    appids = [purchase.get_value(config.json_key_store_appid) for purchase in humble_store.get_latest_purchases()]

    assert all(appids) and len(set(appids)) == 2


def test_the_platform_library_is_listed_then_each_game_described(humble_store, manager, recording_command):
    humble_store.get_latest_purchases()

    assert commands(recording_command) == [
        MANAGER_CMD + ["--list", "--platform", "windows", "--quiet"],
        show_cmd("deponia_windows"),
        show_cmd("tombraider_windows")]


def test_colored_and_padded_lines_are_parsed_like_plain_ones(humble_store, manager):
    manager.listing = "%sdeponia_windows%s\r\n  tombraider_windows  \n" % (GREEN, CLEAR)

    assert appnames(humble_store.get_latest_purchases()) == ["deponia_windows", "tombraider_windows"]


def test_blank_and_chatter_lines_are_skipped(humble_store, manager, recording_command):
    manager.listing = "\ndeponia_windows\n\nWarning: cookie expires soon\n   \ntombraider_windows\n"

    assert appnames(humble_store.get_latest_purchases()) == ["deponia_windows", "tombraider_windows"]
    assert len(recording_command.calls) == 3


def test_odd_names_become_empty_names(humble_store, manager):
    manager.games["deponia_windows"] = {"human_name": None}
    manager.games["tombraider_windows"] = {}

    assert names(humble_store.get_latest_purchases()) == ["", ""]


@pytest.mark.parametrize("listing", ["", None])
def test_no_listing_is_a_failure(humble_store, manager, recording_command, listing):
    manager.listing = listing

    assert humble_store.get_latest_purchases() is None
    assert len(recording_command.calls) == 1
    assert not manager.cache.exists()


@pytest.mark.parametrize("listing", ["\n\n", "Error: login required\n", "Traceback (most recent call last):\n  File x, line 1\n"])
def test_a_listing_without_games_is_a_failure_and_not_cached(humble_store, manager, recording_command, listing):
    manager.listing = listing

    assert humble_store.get_latest_purchases() is None
    assert len(recording_command.calls) == 1
    assert not manager.cache.exists()


@pytest.mark.parametrize("details", ["", None, "not json", "null", "[1]", '"text"'])
def test_an_undescribable_game_fails_the_whole_listing(humble_store, manager, recording_command, details):
    manager.games["deponia_windows"] = details

    assert humble_store.get_latest_purchases() is None
    assert len(recording_command.calls) == 2
    assert not manager.cache.exists()


@pytest.mark.parametrize("tool", ["PythonVenvPython", "HumbleBundleManager"])
def test_purchases_need_python_and_the_manager(humble_store, manager, tools, recording_command, tool):
    del tools[tool]

    assert humble_store.get_latest_purchases() is None
    assert recording_command.calls == []


def test_purchases_pass_their_flags_through(humble_store, manager, recording_command):
    humble_store.get_latest_purchases(verbose = True, pretend_run = True, exit_on_failure = True)

    for call in recording_command.calls:
        assert call["kwargs"] == {"verbose": True, "pretend_run": True, "exit_on_failure": True}


###########################################################
# Caching
###########################################################

def test_purchases_are_cached_for_a_day(humble_store, manager, recording_command):
    humble_store.get_latest_purchases(verbose = True)
    manager.listing = ""

    again = humble_store.get_latest_purchases(verbose = True)

    assert len(recording_command.calls) == 3
    assert appnames(again) == ["deponia_windows", "tombraider_windows"]
    assert names(again) == ["Deponia", "Tomb Raider"]
    assert again[0].get_platform() == config.Platform.COMPUTER_HUMBLE_BUNDLE


def test_the_cache_holds_appids_appnames_and_names(humble_store, manager):
    purchases = humble_store.get_latest_purchases()

    assert json.loads(manager.cache.read_text()) == [
        {config.json_key_store_appid: purchase.get_value(config.json_key_store_appid),
         config.json_key_store_appname: purchase.get_value(config.json_key_store_appname),
         config.json_key_store_name: purchase.get_value(config.json_key_store_name)}
        for purchase in purchases]


def test_cached_appids_are_kept(humble_store, manager):
    first = humble_store.get_latest_purchases()
    again = humble_store.get_latest_purchases()

    assert [p.get_value(config.json_key_store_appid) for p in again] == [
        p.get_value(config.json_key_store_appid) for p in first]


def test_a_cached_empty_library_is_reused(humble_store, manager, recording_command):
    manager.cache.parent.mkdir(parents = True)
    manager.cache.write_text("[]")

    assert humble_store.get_latest_purchases() == []
    assert recording_command.calls == []


def test_a_stale_cache_is_refreshed(humble_store, manager, recording_command):
    humble_store.get_latest_purchases()
    day_ago = time.time() - 25 * 3600
    os.utime(manager.cache, (day_ago, day_ago))

    humble_store.get_latest_purchases()

    assert len(recording_command.calls) == 6


@pytest.mark.parametrize("verbose", [False, True])
@pytest.mark.parametrize("content", [{"not": "a list"}, ["not an entry"], "null", "{broken"])
def test_an_unreadable_cache_is_refetched(humble_store, manager, recording_command, content, verbose):
    manager.cache.parent.mkdir(parents = True)
    manager.cache.write_text(content if isinstance(content, str) else json.dumps(content))

    assert len(humble_store.get_latest_purchases(verbose = verbose)) == 2
    assert len(recording_command.calls) == 3


@pytest.mark.parametrize("verbose", [False, True])
def test_a_failed_cache_write_still_returns_purchases(humble_store, manager, monkeypatch, verbose):
    monkeypatch.setattr(humblebundle.serialization, "write_json_file", lambda **kwargs: False)

    assert len(humble_store.get_latest_purchases(verbose = verbose)) == 2
