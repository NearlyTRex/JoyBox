# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import commandoptions, sandbox

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted,
# so this directory's own conftest cannot shadow the suite's top level one.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def installed_runners(monkeypatch):
    # Neither runner is installed on the machine running the tests, and the
    # lookup raises rather than returning nothing.
    monkeypatch.setattr(sandbox, "get_wine_command", lambda: "/tools/wine")
    monkeypatch.setattr(sandbox, "get_sandboxie_command", lambda: "/tools/start.exe")


@pytest.fixture
def linux(monkeypatch, installed_runners):
    monkeypatch.setattr(sandbox.platform_info, "is_wine_platform", lambda: True)
    monkeypatch.setattr(sandbox.platform_info, "is_sandboxie_platform", lambda: False)


@pytest.fixture
def windows(monkeypatch, installed_runners):
    monkeypatch.setattr(sandbox.platform_info, "is_wine_platform", lambda: False)
    monkeypatch.setattr(sandbox.platform_info, "is_sandboxie_platform", lambda: True)


@pytest.fixture
def cached_game(monkeypatch):
    monkeypatch.setattr(sandbox.commandbase, "is_windows_executable_command", lambda cmd: True)
    monkeypatch.setattr(sandbox.commandbase, "is_cached_game_command", lambda cmd: True)
    monkeypatch.setattr(sandbox.commandbase, "is_local_sandboxed_program_command", lambda cmd: False)


@pytest.fixture
def wine_prefix(tmp_path):
    prefix = tmp_path / "prefix"
    (prefix / "dosdevices").mkdir(parents = True)
    (prefix / "drive_c").mkdir()
    entry = commandoptions.CommandOptions()
    entry.set_is_wine_prefix(True)
    entry.set_prefix_dir(str(prefix))
    return entry
