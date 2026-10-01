# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox.stores import epic

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def epic_store(isolated_settings, tmp_path):
    install_dir = tmp_path / "epic"
    install_dir.mkdir()
    isolated_settings.set_value("UserData.Epic", "epic_username", "player")
    isolated_settings.set_value("UserData.Epic", "epic_install_dir", str(install_dir))
    return epic.Epic()


@pytest.fixture
def tools(monkeypatch):
    installed = {"PythonVenvPython": "/tools/python", "Legendary": "/tools/legendary"}
    monkeypatch.setattr(epic.programs, "is_tool_installed", lambda name: name in installed)
    monkeypatch.setattr(epic.programs, "get_tool_program", lambda name: installed.get(name))
    return installed


@pytest.fixture
def no_manifest(monkeypatch):
    class EmptyManifest:
        def find_entry_by_name(self, **kwargs):
            return None
    monkeypatch.setattr(epic.storebase.manifest, "get_manifest_instance", lambda: EmptyManifest())
