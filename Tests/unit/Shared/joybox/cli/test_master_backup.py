# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import master_backup


###########################################################
# Destination list
#
# master_backup runs unattended, so a misspelled destination must stop the run
# rather than quietly back up to fewer lockers.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, master_backup)
    harness.backups = []
    monkeypatch.setattr(master_backup.masterbackup, "run_master_backup",
                        lambda **kwargs: harness.backups.append(kwargs["remote_locker_types"]) or True)
    return harness


def test_known_destinations_are_backed_up(tool):
    tool.run("--no-preview", "-r", "Hetzner, Gdrive,")

    assert tool.backups == [[config.LockerType.HETZNER, config.LockerType.GDRIVE]]


def test_an_unknown_destination_stops_the_run(tool):
    assert tool.exit_code("--no-preview", "-r", "Hetzner,Gdirve") != 0
    assert tool.errors == ["Unknown locker type: Gdirve"]
    assert tool.backups == []


###########################################################
# Preview and outcome
###########################################################

@pytest.fixture
def previewed(tool, monkeypatch):

    class FakeLockerInfo:
        def __init__(self, locker_type):
            self.locker_type = locker_type

        def get_locker_name(self):
            return "Local"

    monkeypatch.setattr(master_backup.lockerinfo, "LockerInfo", FakeLockerInfo)
    return tool


def test_an_empty_destination_list_stops_the_run(tool):
    tool.exit_code("--no-preview", "-r", " , ")
    assert tool.errors == ["No valid remote locker types specified"]


def test_the_preview_lists_the_sidecar_phase_only_when_rebuilding(previewed):
    previewed.run("-r", "Hetzner")
    previewed.run("-r", "Hetzner", "--no_rebuild_sidecars", "--recycle_orphans")

    rebuilding, skipping = [details for _, details in previewed.previews]
    assert "Destinations: Hetzner" in rebuilding
    assert "Orphan handling: keep (additive only)" in rebuilding
    assert rebuilding[-1].startswith("Phase 3")
    assert "Orphan handling: recycle to .recycle_bin" in skipping
    assert "Rebuild hash sidecars: No" in skipping
    assert not skipping[-1].startswith("Phase 3")


def test_a_declined_preview_backs_up_nothing(previewed):
    previewed.confirm = False

    previewed.run()

    assert previewed.backups == []


def test_a_failed_backup_exits_with_an_error(tool, monkeypatch):
    monkeypatch.setattr(master_backup.masterbackup, "run_master_backup", lambda **kwargs: False)

    assert tool.exit_code("--no-preview") == 1
    assert tool.errors == ["Master backup failed"]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, master_backup)
