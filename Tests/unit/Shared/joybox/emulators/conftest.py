# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import release

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted,
# so this directory's own conftest cannot shadow the suite's top level one.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


# The stored-release restore, recorded; each test file supplies its own program_paths.
# emulator_helpers is importable only once the path above is set, so it is imported here
@pytest.fixture
def stored(monkeypatch, program_paths):
    from emulator_helpers import Release
    fake = Release()
    monkeypatch.setattr(release, "setup_stored_release", fake)
    return fake
