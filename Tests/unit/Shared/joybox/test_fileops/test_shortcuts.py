# Imports
import os
import types

# Local imports
from joybox import fileops
from joybox import modules
from joybox import programs
from fileops_helpers import write


###########################################################
# Windows shortcuts
###########################################################

def fake_pylnk(monkeypatch, work_dir = None, arguments = None, link_path = "C:\\Games\\Title\\game.exe", raises = False):
    class Lnk:
        def __init__(self, path):
            if raises:
                raise ValueError("corrupt shortcut")
            self._link_info = types.SimpleNamespace(path = link_path) if link_path else None
            self.link_flags = types.SimpleNamespace(
                HasWorkingDir = work_dir is not None,
                HasArguments = arguments is not None)
            self.work_dir = work_dir
            self.arguments = arguments
    module = types.SimpleNamespace(Lnk = Lnk)
    monkeypatch.setattr(programs, "get_tool_program", lambda name: "pylnk.py")
    monkeypatch.setattr(modules, "import_python_module_file", lambda module_path, module_name: module)


def make_shortcut(tmp_path):
    path = tmp_path / "game.lnk"
    path.write_bytes(b"")
    return str(path)


def test_link_info_of_a_plain_shortcut(tmp_path, monkeypatch):
    fake_pylnk(monkeypatch)
    info = fileops.get_link_info(make_shortcut(tmp_path), str(tmp_path))
    target = os.path.join(str(tmp_path), "Games", "Title", "game.exe")
    assert info == {"target": target, "cwd": os.path.dirname(target), "args": []}


def test_link_info_with_an_absolute_working_directory_and_arguments(tmp_path, monkeypatch):
    fake_pylnk(monkeypatch, work_dir = "C:\\Games\\Data", arguments = "-fullscreen \"My Save\"\x00")
    info = fileops.get_link_info(make_shortcut(tmp_path), str(tmp_path))
    assert info["cwd"] == os.path.join(str(tmp_path), "Games", "Data")
    assert info["args"] == ["-fullscreen", "My Save"]


def test_link_info_with_a_relative_working_directory(tmp_path, monkeypatch):
    fake_pylnk(monkeypatch, work_dir = "bin")
    info = fileops.get_link_info(make_shortcut(tmp_path), str(tmp_path))
    assert info["cwd"] == os.path.join(str(tmp_path), "Games", "Title", "bin")


def test_link_info_without_a_target(tmp_path, monkeypatch):
    fake_pylnk(monkeypatch, link_path = None)
    assert fileops.get_link_info(make_shortcut(tmp_path), str(tmp_path))["target"] == ""


def test_link_info_of_a_corrupt_shortcut(tmp_path, monkeypatch):
    fake_pylnk(monkeypatch, raises = True)
    assert fileops.get_link_info(make_shortcut(tmp_path), str(tmp_path))["target"] == ""


def test_link_info_rejects_bad_inputs(tmp_path, monkeypatch):
    fake_pylnk(monkeypatch)
    shortcut = make_shortcut(tmp_path)
    other = write(tmp_path / "game.txt")
    empty = {"target": "", "cwd": "", "args": []}
    assert fileops.get_link_info(str(tmp_path / "missing.lnk"), str(tmp_path)) == empty
    assert fileops.get_link_info(other, str(tmp_path)) == empty
    assert fileops.get_link_info(shortcut, str(tmp_path / "missing")) == empty
