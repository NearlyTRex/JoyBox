# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import playstation

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted,
# so this directory's own conftest cannot shadow the suite's top level one.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


###########################################################
# Tool wrappers
#
# Every wrapper builds an argument list for a tool that is not installed here.
# Recording the list pins the invocation: a mode flag in the wrong place, or a
# key that never reaches the command, only shows up on a real disc image.
###########################################################


@pytest.fixture
def installed(monkeypatch):
    from playstation_helpers import TOOL_PATHS
    monkeypatch.setattr(playstation.programs, "is_tool_installed", lambda name: name in TOOL_PATHS)
    monkeypatch.setattr(playstation.programs, "get_tool_program", lambda name: TOOL_PATHS.get(name))
    return TOOL_PATHS


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(playstation.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(playstation.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def existing_output(monkeypatch):
    monkeypatch.setattr(playstation.os.path, "exists", lambda path: True)


@pytest.fixture
def key_file(tmp_path):
    from playstation_helpers import FAKE_DISC_KEY
    target = tmp_path / "game.dkey"
    target.write_text(FAKE_DISC_KEY)
    return str(target)


@pytest.fixture
def venv_only(monkeypatch):
    # The interpreter is there but the script it would run is not.
    from playstation_helpers import TOOL_PATHS
    monkeypatch.setattr(playstation.programs, "is_tool_installed", lambda name: name == "PythonVenvPython")
    monkeypatch.setattr(playstation.programs, "get_tool_program", lambda name: TOOL_PATHS.get(name))
