# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import list_dupes


###########################################################
# Listing duplicates
###########################################################

JDUPES_PATH = "/usr/bin/jdupes"


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, list_dupes)
    harness.commands = []
    harness.code = 0
    harness.installed = True
    monkeypatch.setattr(list_dupes.programs, "is_tool_installed", lambda name: harness.installed)
    monkeypatch.setattr(list_dupes.programs, "get_tool_program", lambda name: JDUPES_PATH)

    def run_command(cmd, **kwargs):
        harness.commands.append(cmd)
        return harness.code

    monkeypatch.setattr(list_dupes.command, "run_returncode_command", run_command)
    return harness


def test_jdupes_searches_the_input_recursively(tool, tmp_path):
    tool.run("-i", str(tmp_path))

    assert tool.commands == [[JDUPES_PATH, "--recurse", "--print-summarize", "--size", str(tmp_path)]]


def test_a_missing_jdupes_stops_before_listing(tool, tmp_path):
    tool.installed = False

    assert tool.exit_code("-i", str(tmp_path)) != 0

    assert tool.errors == ["JDupes was not found"]
    assert tool.commands == []


def test_a_failed_listing_exits_with_an_error(tool, tmp_path):
    tool.code = 2

    assert tool.exit_code("-i", str(tmp_path)) != 0

    assert tool.errors == ["List command failed with code 2"]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, list_dupes)
