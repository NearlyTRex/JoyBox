# Imports
import os
import sys

# Third-party imports
import pytest

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted,
# so this directory's own conftest cannot shadow the suite's top level one.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def processes(monkeypatch):
    from command_helpers import FakeProcesses
    return FakeProcesses(monkeypatch)


@pytest.fixture
def logged(monkeypatch):
    from command_helpers import LogRecorder
    return LogRecorder(monkeypatch)
