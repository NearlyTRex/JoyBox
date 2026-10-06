# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import setup_game_assets


###########################################################
# Asset setup
###########################################################

def test_assets_are_set_up_with_the_common_flags(monkeypatch, isolated_settings):
    tool = CommandHarness(monkeypatch, setup_game_assets)
    calls = []
    monkeypatch.setattr(setup_game_assets.setup, "setup_assets", lambda **kwargs: calls.append(kwargs))

    tool.run("-v", "-x")

    assert calls == [{"verbose": True, "pretend_run": False, "exit_on_failure": True}]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, setup_game_assets)
