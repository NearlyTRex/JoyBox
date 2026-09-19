# Imports
import pytest

# Local imports
from joybox import ollama


###########################################################
# Action dispatch
#
# The action layer moved here out of ollama_tool.py, which reached into a
# module-global args object. Every action now takes the same keyword signature
# so the CLI can dispatch without knowing which options each one reads - and so
# the dispatch is testable without a running Ollama.
###########################################################

def test_the_documented_actions_exist():

    # These names are the tool's positional argument, so dropping one silently
    # breaks a documented command line.
    for action in ["list", "available", "best", "pull", "delete", "info", "harness"]:
        assert action in ollama.get_action_keys()


def test_every_action_is_callable():
    for action, handler in ollama.ACTIONS.items():
        assert callable(handler), f"{action} is not callable"


def test_every_action_accepts_the_shared_signature():

    # Dispatch passes all four keywords to whichever action was chosen, so an
    # action missing one raises TypeError at call time rather than at import.
    import inspect
    for action, handler in ollama.ACTIONS.items():
        parameters = inspect.signature(handler).parameters
        for keyword in ["model_name", "purpose", "harness", "show_all"]:
            assert keyword in parameters, f"{action} does not accept {keyword}"


def test_an_unknown_action_fails_rather_than_raising():

    # main() returns this straight to run_main, which turns False into exit 1.
    assert ollama.run_action("nonsense") is False


def test_dispatch_forwards_every_option(monkeypatch):
    received = {}

    def fake_action(model_name = None, purpose = None, harness = None, show_all = False):
        received.update({
            "model_name": model_name,
            "purpose": purpose,
            "harness": harness,
            "show_all": show_all,
        })
        return True

    monkeypatch.setitem(ollama.ACTIONS, "list", fake_action)

    assert ollama.run_action(
        "list",
        model_name = "llama3",
        purpose = "tools",
        harness = "codex",
        show_all = True) is True

    assert received == {
        "model_name": "llama3",
        "purpose": "tools",
        "harness": "codex",
        "show_all": True,
    }


def test_dispatch_returns_what_the_action_returns(monkeypatch):
    monkeypatch.setitem(ollama.ACTIONS, "list", lambda **kwargs: False)
    assert ollama.run_action("list") is False


###########################################################
# Harnesses
###########################################################

def test_the_default_harness_is_a_known_one():
    assert ollama.DEFAULT_HARNESS in ollama.HARNESSES


def test_every_harness_has_a_display_name():
    for key, harness in ollama.HARNESSES.items():
        assert harness.get("name"), f"harness {key} has no name"


def test_harness_keys_match_the_harness_table():
    assert sorted(ollama.get_harness_keys()) == sorted(ollama.HARNESSES.keys())
