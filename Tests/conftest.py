# Imports
import os
import sys

# Third-party imports
import pytest

###########################################################
# Path wiring
#
# Both trees are consumed off disk via sys.path rather than installed, exactly
# as Scripts/bin/*.py and bootstrap.py do it. Tests have to wire the same paths
# or nothing imports.
###########################################################

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
SHARED_DIR = os.path.join(REPO_ROOT, "Shared")
BOOTSTRAP_DIR = os.path.join(REPO_ROOT, "Bootstrap")
SCRIPTS_BIN_DIR = os.path.join(REPO_ROOT, "Scripts", "bin")

for _path in (TESTS_DIR, SHARED_DIR, BOOTSTRAP_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

###########################################################
# Path fixtures
###########################################################

@pytest.fixture(scope = "session")
def repo_root():
    return REPO_ROOT

@pytest.fixture(scope = "session")
def shared_dir():
    return SHARED_DIR

@pytest.fixture(scope = "session")
def bootstrap_dir():
    return BOOTSTRAP_DIR

@pytest.fixture(scope = "session")
def scripts_bin_dir():
    return SCRIPTS_BIN_DIR

@pytest.fixture(scope = "session")
def installer_files(bootstrap_dir):
    # Every installer module, as (name, path) pairs
    installers_dir = os.path.join(bootstrap_dir, "installers")
    found = []
    for filename in sorted(os.listdir(installers_dir)):
        if filename.startswith("installer_") and filename.endswith(".py"):
            found.append((filename[:-3], os.path.join(installers_dir, filename)))
    return found

@pytest.fixture(scope = "session")
def script_files(scripts_bin_dir):
    # Every CLI entry point under Scripts/bin, as (name, path) pairs
    found = []
    for filename in sorted(os.listdir(scripts_bin_dir)):
        if filename.endswith(".py") and not filename.startswith("_"):
            found.append((filename[:-3], os.path.join(scripts_bin_dir, filename)))
    return found

###########################################################
# Settings isolation
#
# joybox.settings is process-global: a parser plus an in-memory overlay that
# set_value writes to. Without isolation a test that sets a value leaks it into
# every test that runs afterwards, in whatever order pytest happens to pick.
###########################################################

@pytest.fixture
def isolated_settings(tmp_path):
    from joybox import settings, default_settings

    config_path = os.path.join(str(tmp_path), "JoyBox.ini")
    default_settings.create_default_config_file(config_path)

    settings.reset()
    settings.set_settings_file(config_path)

    # Values every server component expects to be non-empty
    settings.set_value("UserData.Servers", "domain_name", "joybox.test")
    settings.set_value("UserData.Servers", "domain_contact", "nobody@joybox.test")

    yield settings

    settings.reset()

###########################################################
# Connection double
###########################################################

@pytest.fixture
def recording_connection():
    from fakes import RecordingConnection
    return RecordingConnection()


###########################################################
# External tools
###########################################################

@pytest.fixture
def recording_command(monkeypatch):
    # Records what a wrapper would run instead of running it. Every disc image
    # wrapper goes through joybox.command, so this is the one seam.
    from fakes import RecordingCommand
    return RecordingCommand(monkeypatch)


def tool_path(name):
    from joybox import programs
    try:
        if not programs.is_tool_installed(name):
            return None
        return programs.get_tool_program(name)
    except Exception:
        return None


@pytest.fixture
def requires_tool(request):
    for marker in request.node.iter_markers("requires_tool"):
        for name in marker.args:
            if not tool_path(name):
                pytest.skip("%s is not installed" % name)
