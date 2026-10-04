# Imports
import sys

# Third-party imports
import pytest

# Local imports
from joybox import config, system
from joybox.cli import locker_sync_tool


###########################################################
# Secondary list
#
# A misspelled secondary must stop the run rather than quietly sync fewer
# lockers.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    state = {"syncs": [], "errors": []}
    monkeypatch.setattr(locker_sync_tool.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(locker_sync_tool.logger, "setup_logging", lambda: None)
    monkeypatch.setattr(locker_sync_tool.lockersync, "sync_lockers",
                        lambda **kwargs: state["syncs"].append(kwargs["secondary_locker_types"]) or True)
    log_error = locker_sync_tool.logger.log_error

    def record_error(message, **kwargs):
        state["errors"].append(message)
        log_error(message, **kwargs)

    monkeypatch.setattr(locker_sync_tool.logger, "log_error", record_error)

    def run(*extra):
        monkeypatch.setattr(sys, "argv", ["locker_sync_tool", "--no-preview", *extra])
        return system.run_main(locker_sync_tool.main)

    state["run"] = run
    return state


def test_known_secondaries_are_synced(tool):
    tool["run"]("-s", "Gdrive, External")

    assert tool["syncs"] == [[config.LockerType.GDRIVE, config.LockerType.EXTERNAL]]


def test_an_unknown_secondary_stops_the_run(tool):
    with pytest.raises(SystemExit) as raised:
        tool["run"]("-s", "Gdrive,Extrenal")
    assert raised.value.code != 0
    assert tool["errors"] == ["Unknown locker type: Extrenal"]
    assert tool["syncs"] == []
