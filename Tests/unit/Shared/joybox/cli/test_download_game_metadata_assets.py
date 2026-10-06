# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, FakeGameInfo, assert_entry_points
from joybox import config
from joybox.cli import download_game_metadata_assets as tool_module


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, tool_module)
    harness.games = [FakeGameInfo("Alpha"), FakeGameInfo("Beta")]
    harness.results = {}
    harness.calls = []
    monkeypatch.setattr(tool_module.gameinfo, "iterate_selected_game_infos", lambda **kwargs: iter(harness.games))

    def fake_download(game_info, asset_type, **kwargs):
        harness.calls.append((game_info.get_name(), asset_type, kwargs))
        return harness.results.get(game_info.get_name(), True)
    monkeypatch.setattr(tool_module.collection, "download_metadata_asset", fake_download)
    return harness


def test_the_asset_type_is_required(tool, capsys):
    assert tool.exit_code("--no-preview") == 2
    assert "--asset_type" in capsys.readouterr().err
    assert tool.calls == []


def test_every_selected_game_gets_the_asset(tool):
    tool.run("-t", "BoxFront", "-l", "Local", "-e")

    assert [(name, asset_type) for name, asset_type, _ in tool.calls] == [
        ("Alpha", config.AssetType.BOXFRONT), ("Beta", config.AssetType.BOXFRONT)]
    assert all(kwargs["skip_existing"] for _, _, kwargs in tool.calls)
    assert all(kwargs["locker_type"] == config.LockerType.LOCAL for _, _, kwargs in tool.calls)
    assert [title for title, _ in tool.previews] == ["Download metadata assets (BoxFront)"]


def test_no_preview_skips_the_prompt(tool):
    tool.run("-t", "Video", "--no-preview")

    assert tool.previews == []
    assert len(tool.calls) == 2


def test_a_cancelled_preview_downloads_nothing(tool):
    tool.confirm = False

    tool.run("-t", "BoxFront")

    assert tool.calls == []


def test_a_failed_download_quits_with_an_error(tool):
    tool.results["Alpha"] = False

    assert tool.exit_code("-t", "BoxFront", "--no-preview") != 0
    assert [name for name, _, _ in tool.calls] == ["Alpha"]


def test_run_goes_through_the_shared_error_handling(tool):
    tool.run("-t", "Label", "--no-preview")

    assert len(tool.calls) == 2


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, tool_module)
