# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox.collection import purchase

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def collection(monkeypatch):
    from purchase_helpers import FakeStore
    # Everything the import writes to, recorded rather than written.
    state = {
        "store": FakeStore(),
        "ignores": {},
        "matches": [],
        "answers": ["y", "Chosen Name"],
        "created_json": [],
        "created_metadata": [],
        "added_ignores": [],
        "json_ok": True,
        "metadata_ok": True,
    }

    monkeypatch.setattr(
        purchase.stores, "get_store_by_categories",
        lambda *args, **kwargs: state["store"])
    monkeypatch.setattr(
        purchase, "get_game_json_ignore_entries", lambda **kwargs: state["ignores"])
    monkeypatch.setattr(
        purchase.serialization, "search_json_files", lambda **kwargs: state["matches"])
    monkeypatch.setattr(
        purchase.environment, "get_json_metadata_dir", lambda **kwargs: "/json")
    monkeypatch.setattr(
        purchase.prompts, "prompt_for_value",
        lambda message, default_value = None, **kwargs: (
            state["answers"].pop(0) if state["answers"] else default_value))

    def create_game_json_file(**kwargs):
        state["created_json"].append(kwargs)
        return state["json_ok"]

    def create_game_metadata_entry(**kwargs):
        state["created_metadata"].append(kwargs)
        return state["metadata_ok"]

    def add_game_json_ignore_entry(**kwargs):
        state["added_ignores"].append(kwargs)
        return True

    monkeypatch.setattr(purchase, "create_game_json_file", create_game_json_file)
    monkeypatch.setattr(purchase, "create_game_metadata_entry", create_game_metadata_entry)
    monkeypatch.setattr(purchase, "add_game_json_ignore_entry", add_game_json_ignore_entry)
    return state
