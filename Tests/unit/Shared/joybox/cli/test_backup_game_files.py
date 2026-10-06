# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, FakeGameInfo, assert_entry_points
from joybox import config
from joybox.cli import backup_game_files


###########################################################
# Store backups
###########################################################

@pytest.fixture
def tool(monkeypatch):
    harness = CommandHarness(monkeypatch, backup_game_files)
    harness.games = [FakeGameInfo("Alpha"), FakeGameInfo("Beta")]
    harness.backed_up = []
    harness.failing = set()

    def backup(game_info, locker_type, **kwargs):
        harness.backed_up.append((game_info.get_name(), locker_type))
        return game_info.get_name() not in harness.failing

    monkeypatch.setattr(backup_game_files.gameinfo, "iterate_selected_game_infos",
        lambda parser, generation_mode, **kwargs: iter(harness.games))
    monkeypatch.setattr(backup_game_files.collection, "backup_game_files", backup)
    return harness


def test_every_selected_game_is_backed_up_to_the_locker(tool):
    tool.run("-l", "Local")

    assert tool.previews == [("Backup game files (store -> Local)", ["Alpha", "Beta"])]
    assert tool.backed_up == [("Alpha", config.LockerType.LOCAL), ("Beta", config.LockerType.LOCAL)]


def test_a_declined_preview_backs_up_nothing(tool):
    tool.confirm = False

    tool.run()

    assert tool.backed_up == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_a_failed_backup_stops_the_run(tool):
    tool.failing.add("Alpha")

    assert tool.exit_code("--no-preview") != 0
    assert [name for name, _ in tool.backed_up] == ["Alpha"]
    assert tool.errors == ["Backup of game files failed!"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, backup_game_files)
