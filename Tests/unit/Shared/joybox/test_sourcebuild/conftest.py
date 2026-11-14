# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import sourcebuild

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture(autouse = True)
def quiet_logs(monkeypatch):
    errors = []
    monkeypatch.setattr(sourcebuild.logger, "log_error", lambda message, *args, **kwargs: errors.append(str(message)))
    monkeypatch.setattr(sourcebuild.logger, "log_warning", lambda *args, **kwargs: None)
    return errors


@pytest.fixture
def webpage_url(monkeypatch):
    holder = {"url": None, "asked": []}

    def get_matching_url(**kwargs):
        holder["asked"].append(kwargs)
        return holder["url"]

    monkeypatch.setattr(sourcebuild.webpage, "get_matching_url", get_matching_url)
    return holder


@pytest.fixture
def backups(monkeypatch):
    calls = []

    def backup(src, dest_rel_path, **kwargs):
        calls.append((src, dest_rel_path, kwargs))
        return True

    monkeypatch.setattr(
        sourcebuild.locker, "convert_to_relative_path", lambda path: "relative/" + os.path.basename(path))
    monkeypatch.setattr(sourcebuild.locker, "backup", backup)
    return calls


@pytest.fixture
def builder(tmp_path, monkeypatch):
    # Source checkouts, archive downloads, extraction and the build command
    # all write into a real scratch directory; nothing external runs.
    from file_helpers import write
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
        sourcebuild.fileops, "create_temporary_directory", lambda **kwargs: (True, str(scratch)))
    monkeypatch.setattr(sourcebuild.network, "download_git_url", download_git_url)
    monkeypatch.setattr(sourcebuild.network, "download_url", download_url)
    monkeypatch.setattr(sourcebuild.archive, "extract_archive", extract_archive)
    monkeypatch.setattr(sourcebuild.command, "run_returncode_command", run_returncode_command)
    monkeypatch.setattr(sourcebuild.programs, "get_tool_program", lambda name: name)
    monkeypatch.setattr(sourcebuild.environment, "get_tools_root_dir", lambda: state["tools_root"])
    return state
