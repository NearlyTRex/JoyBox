# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import coverage_tool


###########################################################
# coverage_tool
#
# The command is a thin wrapper: every option reaches testcoverage.run_action,
# and its result decides the exit status.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, coverage_tool)
    command.action = Recorder(result = True)
    monkeypatch.setattr(coverage_tool.testcoverage, "run_action", command.action)
    return command


def test_report_is_the_default_action(tool):
    tool.main()

    call = tool.action.calls[0]
    assert call["action"] == coverage_tool.testcoverage.ACTION_REPORT
    assert (call["module"], call["limit"], call["output_file"]) == (None, 20, None)
    assert (call["show_source"], call["include_integration"]) == (False, False)


def test_options_reach_the_action(tool):
    tool.main("run", "-m", "cli/backup_tool.py", "-n", "5", "-o", "report.md", "--source", "--integration", "-v", "-p", "-x")

    call = tool.action.calls[0]
    assert call["action"] == "run"
    assert (call["module"], call["limit"], call["output_file"]) == ("cli/backup_tool.py", 5, "report.md")
    assert (call["show_source"], call["include_integration"]) == (True, True)
    assert (call["verbose"], call["pretend_run"], call["exit_on_failure"]) == (True, True, True)


def test_a_failed_action_exits_with_an_error(tool):
    tool.action.result = False

    assert tool.exit_code("report") == 1
    assert tool.errors == ["Script completed with errors"]


def test_a_successful_action_reports_success(tool):
    tool.run("report")

    assert tool.infos == ["Script completed successfully"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, coverage_tool)
