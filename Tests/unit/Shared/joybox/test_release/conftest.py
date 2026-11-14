# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import release

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def github(monkeypatch):
    holder = {"json": None, "urls": []}

    def get_remote_json(url, **kwargs):
        holder["urls"].append(url)
        return holder["json"]

    monkeypatch.setattr(release.network, "get_remote_json", get_remote_json)
    return holder


@pytest.fixture
def downloads(monkeypatch):
    calls = []
    monkeypatch.setattr(
        release, "download_general_release",
        lambda **kwargs: calls.append(kwargs) or True)
    return calls


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    # The archive, the scratch directory it unpacks into, and the install
    # target, with the extractor standing in for a real 7-Zip run.
    from file_helpers import write
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    install_dir = tmp_path / "install"
    payload = {"files": ["tool.sh", os.path.join("data", "assets.bin")], "extracted": []}

    monkeypatch.setattr(
        release.fileops, "create_temporary_directory",
        lambda **kwargs: (True, str(scratch)))

    def extract_archive(archive_file, extract_dir, **kwargs):
        payload["extracted"].append(archive_file)
        for relative in payload["files"]:
            write(os.path.join(extract_dir, relative), "unpacked")
        return True

    monkeypatch.setattr(release.archive, "extract_archive", extract_archive)

    return {
        "root": tmp_path,
        "scratch": str(scratch),
        "install_dir": str(install_dir),
        "payload": payload,
    }


@pytest.fixture
def stored(monkeypatch):
    # Records which archive the selection settled on.
    calls = []
    monkeypatch.setattr(
        release, "setup_general_release",
        lambda **kwargs: calls.append(kwargs) or True)
    return calls


@pytest.fixture
def remote(monkeypatch, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    state = {
        "downloaded": [], "installs": [], "download_ok": True,
        "install_ok": True, "scratch": str(scratch)}

    def download_url(url, **kwargs):
        state["downloaded"].append((url, kwargs))
        return state["download_ok"]

    def setup_general_release(**kwargs):
        state["installs"].append(kwargs)
        return state["install_ok"]

    monkeypatch.setattr(
        release.fileops, "create_temporary_directory", lambda **kwargs: (True, str(scratch)))
    monkeypatch.setattr(release.network, "download_url", download_url)
    monkeypatch.setattr(release, "setup_general_release", setup_general_release)
    return state
