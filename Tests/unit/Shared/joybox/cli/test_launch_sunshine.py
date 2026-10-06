# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import launch_sunshine


###########################################################
# Launching Sunshine
###########################################################

SUNSHINE_PATH = "/opt/sunshine/sunshine"


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, launch_sunshine)
    harness.commands = []
    harness.code = 0
    harness.installed = True
    monkeypatch.setattr(launch_sunshine.programs, "is_tool_installed", lambda name: harness.installed)
    monkeypatch.setattr(launch_sunshine.programs, "get_tool_program", lambda name: SUNSHINE_PATH)

    def run_command(cmd, **kwargs):
        harness.commands.append(cmd)
        return harness.code

    monkeypatch.setattr(launch_sunshine.command, "run_returncode_command", run_command)
    return harness


def test_sunshine_is_launched(tool):
    tool.run()

    assert tool.commands == [[SUNSHINE_PATH]]


def test_a_missing_sunshine_stops_before_launching(tool):
    tool.installed = False

    assert tool.exit_code() != 0

    assert tool.errors == ["Sunshine was not found"]
    assert tool.commands == []


def test_a_failed_launch_exits_with_an_error(tool):
    tool.code = 1

    assert tool.exit_code() != 0

    assert tool.errors == ["Launch command failed with code 1"]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, launch_sunshine)
