# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import build_game_store_purchases


###########################################################
# Store purchases
###########################################################

STORES = [
    (config.Supercategory.ROMS, config.Category.COMPUTER, config.Subcategory.COMPUTER_STEAM),
    (config.Supercategory.ROMS, config.Category.COMPUTER, config.Subcategory.COMPUTER_GOG),
]


@pytest.fixture
def tool(monkeypatch):
    harness = CommandHarness(monkeypatch, build_game_store_purchases)
    harness.built = []
    harness.failing = set()

    def build(game_supercategory, game_category, game_subcategory, **kwargs):
        harness.built.append(game_subcategory)
        return game_subcategory not in harness.failing

    monkeypatch.setattr(build_game_store_purchases.gameinfo, "iterate_selected_game_categories",
        lambda parser, generation_mode: iter(STORES))
    monkeypatch.setattr(build_game_store_purchases.collection, "build_game_store_purchases", build)
    return harness


def test_the_preview_lists_every_store_before_building(tool):
    tool.run()

    assert tool.previews == [("Build game store purchases", ["Roms/Computer/Steam", "Roms/Computer/GOG"])]
    assert tool.built == [config.Subcategory.COMPUTER_STEAM, config.Subcategory.COMPUTER_GOG]


def test_a_declined_preview_builds_nothing(tool):
    tool.confirm = False

    tool.run()

    assert tool.built == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_a_failed_store_stops_the_run(tool):
    tool.failing.add(config.Subcategory.COMPUTER_STEAM)

    assert tool.exit_code("--no-preview") != 0
    assert tool.built == [config.Subcategory.COMPUTER_STEAM]
    assert tool.errors == ["Build of store purchases failed!"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, build_game_store_purchases)
