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


@pytest.fixture(autouse = True)
def quiet_logs(monkeypatch):
    errors = []
    monkeypatch.setattr(release.logger, "log_error", lambda message, *args, **kwargs: errors.append(str(message)))
    monkeypatch.setattr(release.logger, "log_warning", lambda *args, **kwargs: None)
    return errors


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
def webpage_url(monkeypatch):
    holder = {"url": None, "asked": []}

    def get_matching_url(**kwargs):
        holder["asked"].append(kwargs)
        return holder["url"]

    monkeypatch.setattr(release.webpage, "get_matching_url", get_matching_url)
    return holder


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    # The archive, the scratch directory it unpacks into, and the install
    # target, with the extractor standing in for a real 7-Zip run.
    from release_helpers import write
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
def backups(monkeypatch):
    calls = []

    def backup(src, dest_rel_path, **kwargs):
        calls.append((src, dest_rel_path, kwargs))
        return True

    monkeypatch.setattr(
        release.locker, "convert_to_relative_path", lambda path: "relative/" + os.path.basename(path))
    monkeypatch.setattr(release.locker, "backup", backup)
    return calls


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


@pytest.fixture
def builder(tmp_path, monkeypatch):
    # Source checkouts, archive downloads, extraction and the build command
    # all write into a real scratch directory; nothing external runs.
    from release_helpers import write
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    state = {
        "scratch": str(scratch),
        "install_dir": str(tmp_path / "install"),
        "tools_root": str(tmp_path / "tools"),
        "source_files": ["CMakeLists.txt", os.path.join("src", "main.c")],
        "extracted_files": [os.path.join("Tool", "bin", "tool"), os.path.join("Tool", "share", "tool.dat")],
        "outputs": {"make": {"tool": "binary"}, "AppImageTool": {"Tool-x86_64.AppImage": "appimage"}},
        "codes": {},
        "git": [], "downloads": [], "extracts": [], "commands": [],
        "git_ok": True, "download_ok": True, "extract_ok": True,
    }

    def download_git_url(url, output_dir, **kwargs):
        state["git"].append(dict(kwargs, url = url, output_dir = output_dir))
        if state["git_ok"]:
            for relative in state["source_files"]:
                write(os.path.join(output_dir, relative), "source")
        return state["git_ok"]

    def download_url(url, output_file = None, **kwargs):
        state["downloads"].append(dict(kwargs, url = url, output_file = output_file))
        if state["download_ok"]:
            write(output_file, "archive")
        return state["download_ok"]

    def extract_archive(archive_file, extract_dir, **kwargs):
        state["extracts"].append((archive_file, extract_dir))
        if state["extract_ok"]:
            files = state["extracted_files"] if extract_dir.endswith("Extract") else state["source_files"]
            for relative in files:
                write(os.path.join(extract_dir, relative), "extracted")
        return state["extract_ok"]

    def run_returncode_command(cmd, options = None, **kwargs):
        name = cmd if isinstance(cmd, str) else cmd[0]
        cwd = options.get_cwd()
        state["commands"].append({"cmd": cmd, "cwd": cwd, "shell": options.is_shell(), "kwargs": kwargs})
        code = state["codes"].get(name, 0)
        if code == 0:
            for relative, contents in state["outputs"].get(name, {}).items():
                write(os.path.join(cwd, relative), contents)
        return code

    monkeypatch.setattr(
        release.fileops, "create_temporary_directory", lambda **kwargs: (True, str(scratch)))
    monkeypatch.setattr(release.network, "download_git_url", download_git_url)
    monkeypatch.setattr(release.network, "download_url", download_url)
    monkeypatch.setattr(release.archive, "extract_archive", extract_archive)
    monkeypatch.setattr(release.command, "run_returncode_command", run_returncode_command)
    monkeypatch.setattr(release.programs, "get_tool_program", lambda name: name)
    monkeypatch.setattr(release.environment, "get_tools_root_dir", lambda: state["tools_root"])
    return state
