# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox.stores import humblebundle

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def humble_settings(isolated_settings, tmp_path):
    install_dir = tmp_path / "humble"
    install_dir.mkdir()
    for key, value in [
        ("humblebundle_username", "player"),
        ("humblebundle_email", "player@joybox.test"),
        ("humblebundle_platform", "windows"),
        ("humblebundle_auth_token", "token123"),
        ("humblebundle_install_dir", str(install_dir))]:
        isolated_settings.set_value("UserData.HumbleBundle", key, value)
    return isolated_settings


@pytest.fixture
def humble_store(humble_settings):
    return humblebundle.HumbleBundle()


@pytest.fixture
def tools(monkeypatch):
    from humble_helpers import MANAGER_TOOLS
    installed = dict(MANAGER_TOOLS)
    monkeypatch.setattr(humblebundle.programs, "is_tool_installed", lambda name: name in installed)
    monkeypatch.setattr(humblebundle.programs, "get_tool_program", lambda name: installed.get(name))
    return installed


@pytest.fixture
def no_manifest(monkeypatch):
    class EmptyManifest:
        def find_entry_by_name(self, **kwargs):
            return None
    monkeypatch.setattr(humblebundle.storebase.manifest, "get_manifest_instance", lambda: EmptyManifest())
