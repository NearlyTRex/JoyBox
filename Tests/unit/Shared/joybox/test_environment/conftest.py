# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import environment

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted:
# in front, this directory's own conftest would shadow the suite's top level
# one for everything that imports it by name.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


###########################################################
# Environment paths
#
# Almost every path in the collection is composed here. A level dropped or
# added puts a game's files somewhere the rest of the code will not look for
# them, and nothing reports an error - the directory is simply empty.
###########################################################

@pytest.fixture
def roots(monkeypatch):
    from environment_helpers import CACHE, LOCKER, METADATA

    monkeypatch.setattr(environment, "get_locker_root_dir", lambda locker_type = None: LOCKER)
    monkeypatch.setattr(environment, "get_cache_root_dir", lambda: CACHE)
    monkeypatch.setattr(environment, "get_game_metadata_root_dir", lambda: METADATA)
    monkeypatch.setattr(environment, "get_file_metadata_root_dir", lambda: METADATA)
    return LOCKER


@pytest.fixture
def locker(isolated_settings):
    from environment_helpers import LOCKER_ROOT

    isolated_settings.set_value("UserData.Share", "locker_local_mount_path", LOCKER_ROOT)
    isolated_settings.set_value("UserData.Dirs", "tools_dir", "/tmp/joybox-test-tools")
    isolated_settings.set_value("UserData.Dirs", "emulators_dir", "/tmp/joybox-test-emulators")
    return isolated_settings
