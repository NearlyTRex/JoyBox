# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import sync

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted:
# in front, this directory's own conftest would shadow the suite's top level
# one for everything that imports it by name.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def rclone(monkeypatch):
    monkeypatch.setattr(sync.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(sync.programs, "get_tool_program", lambda name: "/tools/rclone")
    return "/tools/rclone"


@pytest.fixture
def no_rclone(monkeypatch):
    monkeypatch.setattr(sync.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(sync.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def quiet(monkeypatch):
    monkeypatch.setattr(sync.logger, "log_info", lambda *args, **kwargs: None)
    monkeypatch.setattr(sync.logger, "log_error", lambda *args, **kwargs: None)
