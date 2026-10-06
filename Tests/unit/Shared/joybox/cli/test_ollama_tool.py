# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import ollama_tool


###########################################################
# Action dispatch
#
# Every option is handed to ollama.run_action, whose result is the exit status.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, ollama_tool)
    harness.actions = []
    harness.result = True

    def run_action(**kwargs):
        harness.actions.append(kwargs)
        return harness.result

    monkeypatch.setattr(ollama_tool.ollama, "run_action", run_action)
    return harness


def test_options_are_passed_to_the_action(tool):
    tool.run("code", "-p", "tools", "-m", "qwen2.5-coder:7b", "-H", "aider", "--all")

    assert tool.actions == [{
        "action": "code", "model_name": "qwen2.5-coder:7b", "purpose": "tools",
        "harness": "aider", "show_all": True}]


def test_a_failed_action_exits_with_an_error(tool):
    tool.result = False

    assert tool.exit_code("list") == 1


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, ollama_tool)
