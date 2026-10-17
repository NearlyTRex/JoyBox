# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import launch_moonlight


###########################################################
# Launching Moonlight
###########################################################

MOONLIGHT_PATH = "/opt/moonlight/Moonlight.AppImage"


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, launch_moonlight)
    harness.commands = []
    harness.code = 0
    harness.installed = True
    harness.settings = isolated_settings
    monkeypatch.setattr(launch_moonlight.programs, "is_tool_installed", lambda name: harness.installed)
    monkeypatch.setattr(launch_moonlight.programs, "get_tool_program", lambda name: MOONLIGHT_PATH)

    def run_command(cmd, **kwargs):
        harness.commands.append(cmd)
        return harness.code

    monkeypatch.setattr(launch_moonlight.command, "run_returncode_command", run_command)
    return harness


def test_without_a_host_the_host_list_opens(tool):
    tool.run()

    assert tool.commands == [[MOONLIGHT_PATH]]


def test_the_configured_host_streams_the_configured_app(tool):
    tool.settings.set_value("Tools.Moonlight", "moonlight_host", "gamebox")

    tool.run()

    assert tool.commands == [[MOONLIGHT_PATH, "stream", "gamebox", "Pegasus"]]


def test_flags_override_the_settings(tool):
    tool.settings.set_value("Tools.Moonlight", "moonlight_host", "gamebox")

    tool.run("--host", "192.168.1.20", "--app", "Steam Big Picture")

    assert tool.commands == [[MOONLIGHT_PATH, "stream", "192.168.1.20", "Steam Big Picture"]]


def test_pairing_pairs_instead_of_streaming(tool):
    tool.run("--host", "gamebox", "--pair")

    assert tool.commands == [[MOONLIGHT_PATH, "pair", "gamebox"]]


def test_pairing_without_a_host_stops_before_launching(tool):
    assert tool.exit_code("--pair") != 0

    assert tool.errors == ["Pairing needs a host, from --host or [Tools.Moonlight] moonlight_host"]
    assert tool.commands == []


def test_a_missing_moonlight_stops_before_launching(tool):
    tool.installed = False

    assert tool.exit_code() != 0

    assert tool.errors == ["Moonlight was not found"]
    assert tool.commands == []


def test_a_failed_launch_exits_with_an_error(tool):
    tool.code = 1

    assert tool.exit_code() != 0

    assert tool.errors == ["Launch command failed with code 1"]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, launch_moonlight)
