# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, FakeGameInfo, assert_entry_points
from joybox import config
from joybox.cli import upload_game_files


###########################################################
# Encrypted uploads
###########################################################

@pytest.fixture
def tool(monkeypatch):
    harness = CommandHarness(monkeypatch, upload_game_files)
    harness.games = [FakeGameInfo("Alpha"), FakeGameInfo("Beta")]
    harness.uploaded = []
    harness.failing = set()
    harness.sources = []

    def games(parser, generation_mode, locker_type, **kwargs):
        harness.sources.append(locker_type)
        return iter(harness.games)

    def upload(game_info, game_root, locker_type, **kwargs):
        harness.uploaded.append((game_info.get_name(), game_root, locker_type))
        return game_info.get_name() not in harness.failing

    monkeypatch.setattr(upload_game_files.gameinfo, "iterate_selected_game_infos", games)
    monkeypatch.setattr(upload_game_files.environment, "get_locker_gaming_files_dir",
        lambda supercategory, category, subcategory, name, locker_type: "/locker/%s/%s" % (locker_type, name))
    monkeypatch.setattr(upload_game_files.collection, "upload_game_files", upload)
    return harness


def test_each_game_uploads_from_its_source_locker_folder(tool):
    tool.run("-l", "Local", "-d", "Hetzner")

    assert tool.sources == [config.LockerType.LOCAL]
    assert tool.previews == [("Upload game files (encrypt and upload to Hetzner)", ["/locker/Local/Alpha", "/locker/Local/Beta"])]
    assert tool.uploaded == [("Alpha", "/locker/Local/Alpha", config.LockerType.HETZNER),
                             ("Beta", "/locker/Local/Beta", config.LockerType.HETZNER)]


def test_an_input_path_replaces_the_derived_folder(tool, tmp_path):
    tool.games = tool.games[:1]

    tool.run("-i", str(tmp_path), "--no-preview")

    assert [root for _, root, _ in tool.uploaded] == [str(tmp_path)]


def test_a_declined_preview_uploads_nothing(tool):
    tool.confirm = False

    tool.run()

    assert tool.uploaded == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_a_failed_upload_stops_the_run(tool):
    tool.failing.add("Alpha")

    assert tool.exit_code("--no-preview") != 0
    assert [name for name, _, _ in tool.uploaded] == ["Alpha"]
    assert tool.errors == ["Upload of game files failed!"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, upload_game_files)
