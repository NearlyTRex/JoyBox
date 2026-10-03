# Imports
import sys

# Third-party imports
import pytest

# Local imports
from joybox import config, system
from joybox.cli import master_backup


###########################################################
# Destination list
#
# master_backup runs unattended, so a misspelled destination must stop the run
# rather than quietly back up to fewer lockers.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    state = {"backups": [], "errors": []}
    monkeypatch.setattr(master_backup.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(master_backup.logger, "setup_logging", lambda: None)
    monkeypatch.setattr(master_backup.masterbackup, "run_master_backup",
                        lambda **kwargs: state["backups"].append(kwargs["remote_locker_types"]) or True)
    log_error = master_backup.logger.log_error

    def record_error(message, **kwargs):
        state["errors"].append(message)
        log_error(message, **kwargs)

    monkeypatch.setattr(master_backup.logger, "log_error", record_error)

    def run(*extra):
        monkeypatch.setattr(sys, "argv", ["master_backup", "--no-preview", *extra])
        return system.run_main(master_backup.main)

    state["run"] = run
    return state


def test_known_destinations_are_backed_up(tool):
    tool["run"]("-r", "Hetzner, Gdrive,")

    assert tool["backups"] == [[config.LockerType.HETZNER, config.LockerType.GDRIVE]]


def test_an_unknown_destination_stops_the_run(tool):
    with pytest.raises(SystemExit) as raised:
        tool["run"]("-r", "Hetzner,Gdirve")
    assert raised.value.code != 0
    assert tool["errors"] == ["Unknown locker type: Gdirve"]
    assert tool["backups"] == []
