# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import nintendo

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


# None of these tools are installed here, so what is pinned is the argument
# list each wrapper builds and what it does with the result. A mode token in
# the wrong place converts nothing and still returns zero.
@pytest.fixture
def installed(monkeypatch):
    from nintendo_helpers import TOOL_PATHS
    tools = dict(TOOL_PATHS)
    monkeypatch.setattr(nintendo.programs, "is_tool_installed", lambda name: name in tools)
    monkeypatch.setattr(nintendo.programs, "get_tool_program", lambda name: tools.get(name))
    return tools

@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(nintendo.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(nintendo.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def existing_output(monkeypatch):
    monkeypatch.setattr(nintendo.os.path, "exists", lambda path: True)


@pytest.fixture
def scratch(monkeypatch, tmp_path):
    # The wrappers stage their work in a temporary directory; handing them a
    # known one makes the intermediate names assertable.
    workspace = tmp_path / "scratch"
    workspace.mkdir()
    monkeypatch.setattr(
        nintendo.fileops, "create_temporary_directory",
        lambda **kwargs: (True, str(workspace)))
    return str(workspace)


@pytest.fixture
def no_scratch(monkeypatch):
    monkeypatch.setattr(
        nintendo.fileops, "create_temporary_directory",
        lambda **kwargs: (False, ""))



@pytest.fixture
def nus_package(tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    (package / "title.tmd").write_bytes(b"tmd")
    (package / "title.tik").write_bytes(b"tik")
    (package / "title.cert").write_bytes(b"cert")
    (package / "00000000.app").write_bytes(b"app")
    (package / "keep.txt").write_text("notes")
    return str(package)

