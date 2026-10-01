# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox.stores import gog

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def gog_store(isolated_settings, tmp_path):
    from gog_helpers import GOG_SETTINGS
    install_dir = tmp_path / "gog"
    install_dir.mkdir()
    for key, value in GOG_SETTINGS + [("gog_includes", ""), ("gog_install_dir", str(install_dir))]:
        isolated_settings.set_value("UserData.GOG", key, value)
    return gog.GOG()


@pytest.fixture
def tools(monkeypatch):
    # Programs by name, and their path config values by (tool, key)
    from gog_helpers import TOOLS, TOOL_PATHS
    state = {"programs": dict(TOOLS), "paths": dict(TOOL_PATHS)}
    monkeypatch.setattr(gog.programs, "is_tool_installed", lambda name: name in state["programs"])
    monkeypatch.setattr(gog.programs, "get_tool_program", lambda name: state["programs"].get(name))
    monkeypatch.setattr(gog.programs, "get_tool_path_config_value",
        lambda name, key: state["paths"].get((name, key)) if name in state["programs"] else None)
    return state


@pytest.fixture
def reachable(monkeypatch):
    # Declares which urls answer, so the probing order is observable.
    state = {"ok": set(), "all": False, "probed": []}

    def is_url_reachable(url):
        state["probed"].append(url)
        if state["all"]:
            return True
        return url in state["ok"]

    monkeypatch.setattr(gog.network, "is_url_reachable", is_url_reachable)
    return state


@pytest.fixture
def no_manifest(monkeypatch):
    class EmptyManifest:
        def find_entry_by_gogid(self, **kwargs):
            return None
        def find_entry_by_name(self, **kwargs):
            return None
    monkeypatch.setattr(gog.manifest, "get_manifest_instance", lambda: EmptyManifest())


@pytest.fixture
def temp_dir(monkeypatch, tmp_path):
    # The single temporary directory a call creates, at a known path
    state = {"path": tmp_path / "gog-temp", "ok": True, "created": 0}

    def create_temporary_directory(**kwargs):
        state["created"] += 1
        if not state["ok"]:
            return (False, "no")
        state["path"].mkdir()
        return (True, str(state["path"]))
    monkeypatch.setattr(gog.fileops, "create_temporary_directory", create_temporary_directory)
    return state
