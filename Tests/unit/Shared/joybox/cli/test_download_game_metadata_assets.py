# Imports
import runpy
import sys

# Third-party imports
import pytest

# Local imports
from joybox import config, system
from joybox.cli import download_game_metadata_assets as tool_module


class FakeGameInfo:

    def __init__(self, name):
        self.name = name

    def get_supercategory(self):
        return config.Supercategory.ROMS

    def get_category(self):
        return config.Category.NINTENDO

    def get_subcategory(self):
        return config.Subcategory.NINTENDO_SWITCH

    def get_name(self):
        return self.name


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    state = {"games": [FakeGameInfo("Alpha"), FakeGameInfo("Beta")], "results": {}, "calls": [], "previews": []}
    monkeypatch.setattr(tool_module.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(tool_module.logger, "setup_logging", lambda: None)
    monkeypatch.setattr(tool_module.gameinfo, "iterate_selected_game_infos", lambda **kwargs: iter(state["games"]))

    def fake_preview(title, details):
        state["previews"].append(title)
        return state.get("confirm", True)
    monkeypatch.setattr(tool_module.prompts, "prompt_for_preview", fake_preview)

    def fake_download(game_info, asset_type, **kwargs):
        state["calls"].append((game_info.get_name(), asset_type, kwargs))
        return state["results"].get(game_info.get_name(), True)
    monkeypatch.setattr(tool_module.collection, "download_metadata_asset", fake_download)

    def run(*extra):
        monkeypatch.setattr(sys, "argv", ["download_game_metadata_assets", *extra])
        return system.run_main(tool_module.main)

    state["run"] = run
    return state


def test_the_asset_type_is_required(tool, capsys):
    with pytest.raises(SystemExit) as raised:
        tool["run"]("--no-preview")
    assert raised.value.code == 2
    assert "--asset_type" in capsys.readouterr().err
    assert tool["calls"] == []


def test_every_selected_game_gets_the_asset(tool):
    tool["run"]("-t", "BoxFront", "-l", "Local", "-e")

    assert [(name, asset_type) for name, asset_type, _ in tool["calls"]] == [
        ("Alpha", config.AssetType.BOXFRONT), ("Beta", config.AssetType.BOXFRONT)]
    assert all(kwargs["skip_existing"] for _, _, kwargs in tool["calls"])
    assert all(kwargs["locker_type"] == config.LockerType.LOCAL for _, _, kwargs in tool["calls"])
    assert tool["previews"] == ["Download metadata assets (BoxFront)"]


def test_no_preview_skips_the_prompt(tool):
    tool["run"]("-t", "Video", "--no-preview")

    assert tool["previews"] == []
    assert len(tool["calls"]) == 2


def test_a_cancelled_preview_downloads_nothing(tool):
    tool["confirm"] = False

    tool["run"]("-t", "BoxFront")

    assert tool["calls"] == []


def test_a_failed_download_quits_with_an_error(tool):
    tool["results"]["Alpha"] = False

    with pytest.raises(SystemExit) as raised:
        tool["run"]("-t", "BoxFront", "--no-preview")
    assert raised.value.code != 0
    assert [name for name, _, _ in tool["calls"]] == ["Alpha"]


def test_run_goes_through_the_shared_error_handling(tool, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["download_game_metadata_assets", "-t", "Label", "--no-preview"])

    tool_module.run()

    assert len(tool["calls"]) == 2


def test_running_the_module_starts_the_command(monkeypatch):
    called = []
    monkeypatch.setattr(system, "run_main", lambda main: called.append(main))

    runpy.run_path(tool_module.__file__, run_name = "__main__")

    assert len(called) == 1
