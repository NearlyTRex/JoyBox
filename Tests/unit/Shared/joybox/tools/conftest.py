# Imports
import os
import sys

# Third-party imports
import pytest

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def steps(monkeypatch, isolated_settings):
    from tools_helpers import Steps
    return Steps(monkeypatch)
