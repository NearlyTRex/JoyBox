# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import locker_sync_tool


###########################################################
# Secondary list
#
# A misspelled secondary must stop the run rather than quietly sync fewer
# lockers.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, locker_sync_tool)
    harness.syncs = []
    monkeypatch.setattr(locker_sync_tool.lockersync, "sync_lockers",
                        lambda **kwargs: harness.syncs.append(kwargs["secondary_locker_types"]) or True)
    return harness


def test_known_secondaries_are_synced(tool):
    tool.run("--no-preview", "-s", "Gdrive, External")

    assert tool.syncs == [[config.LockerType.GDRIVE, config.LockerType.EXTERNAL]]


def test_an_unknown_secondary_stops_the_run(tool):
    assert tool.exit_code("--no-preview", "-s", "Gdrive,Extrenal") != 0
    assert tool.errors == ["Unknown locker type: Extrenal"]
    assert tool.syncs == []


###########################################################
# Cache and outcome
###########################################################

def test_an_empty_secondary_list_stops_the_run(tool):
    tool.exit_code("--no-preview", "-s", ", ,")
    assert tool.errors == ["No valid secondary locker types specified"]
    assert tool.syncs == []


def test_clear_cache_empties_the_hash_map_cache_before_syncing(tool, monkeypatch):
    order = []
    monkeypatch.setattr(locker_sync_tool.lockersync, "clear_cache", lambda: order.append("clear"))
    monkeypatch.setattr(locker_sync_tool.lockersync, "sync_lockers", lambda **kwargs: order.append("sync") or True)

    tool.run("--no-preview", "-s", "Gdrive", "--clear_cache")

    assert order == ["clear", "sync"]


def test_a_failed_sync_exits_with_an_error(tool, monkeypatch):
    monkeypatch.setattr(locker_sync_tool.lockersync, "sync_lockers", lambda **kwargs: False)

    assert tool.exit_code("--no-preview", "-s", "Gdrive") == 1
    assert tool.errors == ["Locker sync failed"]


def test_run_goes_through_the_shared_error_handling(tool):
    tool.run("-s", "Gdrive")

    assert tool.syncs == [[config.LockerType.GDRIVE]]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, locker_sync_tool)
