# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import iso

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted,
# so this directory's own conftest cannot shadow the suite's top level one.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(iso.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(iso.programs, "get_tool_program", lambda name: "/tools/xorriso")
    return "/tools/xorriso"


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(iso.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(iso.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def existing_output(monkeypatch):
    monkeypatch.setattr(iso.os.path, "exists", lambda path: True)


@pytest.fixture
def no_archive_fallback(monkeypatch):
    # extract_iso tries the archive path first; force it to the tool path.
    monkeypatch.setattr(iso.archive, "extract_archive", lambda **kwargs: False)


@pytest.fixture
def source_image(tmp_path):
    # extract_iso refuses a source that is not there, so it has to exist.
    target = tmp_path / "Game.iso"
    target.write_bytes(b"x")
    return str(target)


@pytest.fixture
def populated_output(monkeypatch):
    monkeypatch.setattr(iso.paths, "does_directory_contain_files", lambda path, **kwargs: True)


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(iso.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(iso.platform_info, "is_linux_platform", lambda: True)


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(iso.platform_info, "is_windows_platform", lambda: True)
    monkeypatch.setattr(iso.platform_info, "is_linux_platform", lambda: False)


@pytest.fixture
def other_platform(monkeypatch):
    monkeypatch.setattr(iso.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(iso.platform_info, "is_linux_platform", lambda: False)


@pytest.fixture
def mount_states(monkeypatch):
    # Answers is_iso_mounted from a queue: the check before acting, then after.
    def install(*states):
        queue = list(states)
        monkeypatch.setattr(iso, "is_iso_mounted", lambda iso_file, mount_dir: queue.pop(0))
        return queue
    return install
