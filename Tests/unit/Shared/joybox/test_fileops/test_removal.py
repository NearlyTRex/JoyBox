# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import fileops
from fileops_helpers import write, read, tree, fail


###########################################################
# Directory creation and removal
###########################################################

def test_make_directory(tmp_path):
    path = tmp_path / "a" / "b"
    assert fileops.make_directory(str(path), pretend_run = True)
    assert not path.exists()
    assert fileops.make_directory(str(path), verbose = True)
    assert path.is_dir()
    assert fileops.make_directory(str(path))


def test_make_directory_over_a_file(tmp_path):
    path = write(tmp_path / "file")
    assert not fileops.make_directory(path)
    with pytest.raises(SystemExit):
        fileops.make_directory(path, exit_on_failure = True)


def test_make_directory_tolerates_a_racing_creator(tmp_path, monkeypatch):
    path = tmp_path / "dir"
    def racing_makedirs(src, exist_ok = False):
        os.mkdir(src)
        raise FileExistsError(src)
    monkeypatch.setattr(fileops.os, "makedirs", racing_makedirs)
    assert fileops.make_directory(str(path))


def test_remove_file(tmp_path):
    path = write(tmp_path / "file")
    assert fileops.remove_file(path, pretend_run = True)
    assert os.path.exists(path)
    assert fileops.remove_file(path, verbose = True)
    assert not os.path.exists(path)
    assert fileops.remove_file(path)


def test_remove_symlink(tmp_path):
    target = write(tmp_path / "target")
    link = tmp_path / "link"
    os.symlink(target, link)
    assert fileops.remove_symlink(str(link), pretend_run = True)
    assert os.path.lexists(link)
    assert fileops.remove_symlink(str(link), verbose = True)
    assert not os.path.lexists(link)
    assert fileops.remove_symlink(target)
    assert os.path.exists(target)


def test_remove_directory(tmp_path):
    path = tmp_path / "dir"
    write(path / "file")
    assert fileops.remove_directory(str(path), pretend_run = True)
    assert path.exists()
    assert fileops.remove_directory(str(path), verbose = True)
    assert not path.exists()


@pytest.mark.parametrize("function,target,patch", [
    ("remove_file", "file", "remove"),
    ("remove_symlink", "link", "unlink"),
])
def test_removal_failures(tmp_path, monkeypatch, function, target, patch):
    path = write(tmp_path / "file")
    os.symlink(path, tmp_path / "link")
    monkeypatch.setattr(fileops.os, patch, fail)
    remove = getattr(fileops, function)
    assert not remove(str(tmp_path / target))
    with pytest.raises(SystemExit):
        remove(str(tmp_path / target), exit_on_failure = True)


def test_remove_directory_failure(tmp_path, monkeypatch):
    os.makedirs(tmp_path / "dir")
    monkeypatch.setattr(fileops.shutil, "rmtree", fail)
    assert not fileops.remove_directory(str(tmp_path / "dir"))
    with pytest.raises(SystemExit):
        fileops.remove_directory(str(tmp_path / "dir"), exit_on_failure = True)


def test_remove_directory_contents_keeps_the_directory(tmp_path):
    root = tmp_path / "root"
    write(root / "a.txt")
    write(root / "sub" / "b.txt")
    assert fileops.remove_directory_contents(str(root), verbose = True)
    assert root.is_dir()
    assert os.listdir(root) == []


def test_remove_directory_contents_unlinks_directory_symlinks(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    write(outside / "precious.txt")
    os.makedirs(root)
    os.symlink(outside, root / "link")
    assert fileops.remove_directory_contents(str(root))
    assert os.listdir(root) == []
    assert (outside / "precious.txt").exists()


def test_remove_directory_contents_clears_read_only_directories(tmp_path):
    root = tmp_path / "root"
    write(root / "ro" / "inner" / "file.txt")
    os.chmod(root / "ro" / "inner", 0o500)
    os.chmod(root / "ro", 0o500)
    try:
        assert fileops.remove_directory_contents(str(root))
        assert os.listdir(root) == []
    finally:
        for path in [root / "ro", root / "ro" / "inner"]:
            if path.exists():
                os.chmod(path, 0o700)


def test_remove_directory_contents_in_a_pretend_run(tmp_path):
    write(tmp_path / "a.txt")
    assert fileops.remove_directory_contents(str(tmp_path), pretend_run = True)
    assert tree(tmp_path) == {"a.txt"}


def test_remove_directory_contents_failure(tmp_path, monkeypatch):
    write(tmp_path / "a.txt")
    monkeypatch.setattr(fileops.os, "unlink", fail)
    assert not fileops.remove_directory_contents(str(tmp_path))
    with pytest.raises(SystemExit):
        fileops.remove_directory_contents(str(tmp_path), exit_on_failure = True)


###########################################################
# Removal by pattern
###########################################################

def test_remove_by_glob_takes_every_kind_of_match(tmp_path):
    write(tmp_path / "match_file")
    write(tmp_path / "match_dir" / "inner.txt")
    os.symlink(tmp_path / "gone", tmp_path / "match_link")
    write(tmp_path / "keep")
    assert fileops.remove_file_or_directory(str(tmp_path / "match_*"), verbose = True)
    assert os.listdir(tmp_path) == ["keep"]


def test_remove_by_glob_in_a_pretend_run(tmp_path):
    write(tmp_path / "match_file")
    assert fileops.remove_file_or_directory(str(tmp_path / "match_*"), pretend_run = True)
    assert os.listdir(tmp_path) == ["match_file"]


def test_remove_by_glob_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(fileops.glob, "glob", fail)
    assert not fileops.remove_file_or_directory(str(tmp_path / "*"))
    with pytest.raises(SystemExit):
        fileops.remove_file_or_directory(str(tmp_path / "*"), exit_on_failure = True)


def test_remove_object_of_nothing(tmp_path):
    assert not fileops.remove_object(str(tmp_path / "missing"))


###########################################################
# Recycle bin
###########################################################

def recycled(root):
    return tree(os.path.join(root, ".recycle_bin"))


def test_recycle_keeps_the_relative_path(tmp_path):
    src = write(tmp_path / "games" / "save.dat")
    assert fileops.recycle_file(src, str(tmp_path), verbose = True)
    assert not os.path.exists(src)
    assert os.path.join("games", "save.dat") in recycled(tmp_path)


def test_recycle_timestamps_a_name_already_in_the_bin(tmp_path, monkeypatch):
    monkeypatch.setattr(fileops.time, "time", lambda: 1234)
    write(tmp_path / ".recycle_bin" / "save.dat", "old")
    src = write(tmp_path / "save.dat", "new")
    assert fileops.recycle_file(src, str(tmp_path))
    assert read(tmp_path / ".recycle_bin" / "save_1234.dat") == "new"
    assert read(tmp_path / ".recycle_bin" / "save.dat") == "old"


def test_recycle_of_a_missing_file_is_a_no_op(tmp_path):
    assert fileops.recycle_file(str(tmp_path / "missing"), str(tmp_path), verbose = True)


def test_recycle_leaves_the_bin_alone(tmp_path):
    src = write(tmp_path / ".recycle_bin" / "save.dat")
    assert fileops.recycle_file(src, str(tmp_path), verbose = True)
    assert os.path.exists(src)


def test_recycle_of_a_file_outside_the_root_uses_its_name(tmp_path):
    root = tmp_path / "root"
    os.makedirs(root)
    src = write(tmp_path / "rootx" / "save.dat")
    assert fileops.recycle_file(src, str(root))
    assert recycled(root) == {"save.dat"}


def test_recycle_matches_the_bin_by_whole_name(tmp_path):
    src = write(tmp_path / ".recycle_bin_old" / "save.dat")
    assert fileops.recycle_file(src, str(tmp_path))
    assert os.path.join(".recycle_bin_old", "save.dat") in recycled(tmp_path)


def test_empty_recycle_bin(tmp_path):
    write(tmp_path / ".recycle_bin" / "a" / "save.dat")
    assert fileops.empty_recycle_bin(str(tmp_path), verbose = True)
    assert os.listdir(tmp_path / ".recycle_bin") == []
    assert fileops.empty_recycle_bin(str(tmp_path / "elsewhere"), verbose = True)
