# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox.stores import amazon

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def amazon_store(isolated_settings, tmp_path):
    install_dir = tmp_path / "amazon"
    install_dir.mkdir()
    isolated_settings.set_value("UserData.Amazon", "amazon_install_dir", str(install_dir))
    return amazon.Amazon()


@pytest.fixture
def tools(monkeypatch):
    from amazon_helpers import NILE_TOOLS
    installed = dict(NILE_TOOLS)
    monkeypatch.setattr(amazon.programs, "is_tool_installed", lambda name: name in installed)
    monkeypatch.setattr(amazon.programs, "get_tool_program", lambda name: installed.get(name))
    return installed
