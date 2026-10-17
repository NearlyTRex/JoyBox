# Imports
import inspect

# Local imports
from joybox import ollama



###########################################################
# Action dispatch
#
# Every action takes the same keyword signature so the CLI can dispatch without
# knowing which options each one reads.
###########################################################

def test_the_documented_actions_exist():
    # These names are the tool's positional argument.
    missing = [
        action for action in ["list", "available", "best", "pull", "delete", "info", "harness"]
        if action not in ollama.get_action_keys()]

    assert not missing, missing


def test_every_action_is_callable():
    uncallable = [action for action, handler in ollama.ACTIONS.items() if not callable(handler)]

    assert not uncallable, uncallable


def test_every_action_accepts_the_shared_signature():
    # Dispatch passes all four keywords, so a missing one raises at call time.
    missing = [
        (action, keyword) for action, handler in ollama.ACTIONS.items()
        for keyword in ["model_name", "purpose", "harness", "show_all"]
        if keyword not in inspect.signature(handler).parameters]

    assert not missing, missing


def test_an_unknown_action_fails_rather_than_raising():
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
    unnamed = [key for key, harness in ollama.HARNESSES.items() if not harness.get("name")]

    assert not unnamed, unnamed


def test_harness_keys_match_the_harness_table():
    assert sorted(ollama.get_harness_keys()) == sorted(ollama.HARNESSES.keys())
