# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import login_game_stores


###########################################################
# Store logins
###########################################################

STORES = [
    (config.Supercategory.ROMS, config.Category.COMPUTER, config.Subcategory.COMPUTER_STEAM),
    (config.Supercategory.ROMS, config.Category.COMPUTER, config.Subcategory.COMPUTER_GOG),
]


@pytest.fixture
def tool(monkeypatch):
    harness = CommandHarness(monkeypatch, login_game_stores)
    harness.logged_in = []
    harness.failing = set()
    harness.modes = []

    def categories(parser, generation_mode):
        harness.modes.append(generation_mode)
        return iter(STORES)

    def login(game_supercategory, game_category, game_subcategory, **kwargs):
        harness.logged_in.append(game_subcategory)
        return game_subcategory not in harness.failing

    monkeypatch.setattr(login_game_stores.gameinfo, "iterate_selected_game_categories", categories)
    monkeypatch.setattr(login_game_stores.collection, "login_game_store", login)
    return harness


def test_every_selected_store_is_logged_in(tool):
    tool.run("-m", "Custom")

    assert tool.logged_in == [config.Subcategory.COMPUTER_STEAM, config.Subcategory.COMPUTER_GOG]
    assert tool.modes == [config.GenerationModeType.CUSTOM]


def test_a_failed_login_stops_the_run(tool):
    tool.failing.add(config.Subcategory.COMPUTER_STEAM)

    assert tool.exit_code() != 0
    assert tool.logged_in == [config.Subcategory.COMPUTER_STEAM]
    assert tool.errors == ["Login of store failed!"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, login_game_stores)
