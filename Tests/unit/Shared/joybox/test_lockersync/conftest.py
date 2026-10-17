# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import lockersync

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted:
# in front, this directory's own conftest would shadow the suite's top level
# one for everything that imports it by name.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def cache_dir(monkeypatch, tmp_path):
    target = tmp_path / "cache"
    monkeypatch.setattr(
        lockersync.environment, "get_cache_sync_dir", lambda: str(target))
    return target


@pytest.fixture
def messages(monkeypatch):
    # Everything logged, by level
    logged = {"info": [], "warning": [], "error": []}
    monkeypatch.setattr(lockersync.logger, "log_info", logged["info"].append)
    monkeypatch.setattr(lockersync.logger, "log_warning", logged["warning"].append)
    monkeypatch.setattr(lockersync.logger, "log_error", logged["error"].append)
    return logged
