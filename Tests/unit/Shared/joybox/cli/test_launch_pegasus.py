# Imports
import os

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import launch_pegasus


###########################################################
# Launching Pegasus
#
# Pegasus runs from its own directory with JOYBOX_LAUNCH_JSON pointing at the
# launch_game_json command; a failed launch is a non-zero exit.
###########################################################

PEGASUS_PATH = "/opt/pegasus/pegasus-fe"


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, launch_pegasus)
    harness.commands = []
    harness.code = 0
    harness.installed = True
    monkeypatch.setattr(launch_pegasus.programs, "is_tool_installed", lambda name: harness.installed)
    monkeypatch.setattr(launch_pegasus.programs, "get_tool_program", lambda name: PEGASUS_PATH)

    def run_command(cmd, options, **kwargs):
        harness.commands.append((cmd, options))
        return harness.code

    monkeypatch.setattr(launch_pegasus.command, "run_returncode_command", run_command)
    return harness


def test_pegasus_runs_from_its_directory_with_the_launch_command(tool):
    tool.run()

    [(cmd, options)] = tool.commands
    assert cmd == [PEGASUS_PATH]
    assert options.get_cwd() == "/opt/pegasus"
    assert options.get_env_var("JOYBOX_LAUNCH_JSON").endswith("launch_game_json")
    assert "JOYBOX_LAUNCH_JSON" not in os.environ


def test_a_missing_pegasus_stops_before_launching(tool):
    tool.installed = False

    assert tool.exit_code() != 0

    assert tool.errors == ["Pegasus was not found"]
    assert tool.commands == []


def test_a_failed_launch_exits_with_an_error(tool):
    tool.code = 3

    assert tool.exit_code() != 0

    assert tool.errors == ["Launch command failed with code 3"]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, launch_pegasus)
