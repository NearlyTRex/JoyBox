# Imports
import os
import stat

# Third-party imports
import pytest

# Local imports
from joybox import fileops
from fileops_helpers import write, read, fail, mode


###########################################################
# Creation
###########################################################

def test_touch_creates_parents_and_an_empty_file(tmp_path):
    path = str(tmp_path / "a" / "b" / "file.txt")
    assert fileops.touch_file(path, verbose = True)
    assert read(path) == ""


def test_touch_writes_contents(tmp_path):
    path = str(tmp_path / "file.txt")
    assert fileops.touch_file(path, contents = "héllo", encoding = "utf-8")
    assert read(path) == "héllo"
    assert fileops.touch_file(path, contents = "!", contents_mode = "a")
    assert read(path) == "héllo!"


def test_touch_in_a_pretend_run(tmp_path):
    path = tmp_path / "file.txt"
    assert fileops.touch_file(str(path), pretend_run = True)
    assert not path.exists()


def test_touch_reports_a_blocked_parent(tmp_path):
    blocker = write(tmp_path / "blocker")
    path = os.path.join(blocker, "file.txt")
    assert not fileops.touch_file(path)
    with pytest.raises(SystemExit):
        fileops.touch_file(path, exit_on_failure = True)



def test_chmod_a_file(tmp_path):
    path = write(tmp_path / "file.txt")
    assert fileops.chmod_file_or_directory(path, 600, verbose = True)
    assert mode(path) == 0o600


def test_chmod_a_directory_uses_directory_permissions(tmp_path):
    root = tmp_path / "root"
    path = write(root / "sub" / "file.txt")
    assert fileops.chmod_file_or_directory(str(root), 640, dperms = 750)
    assert mode(root) == 0o750
    assert mode(root / "sub") == 0o750
    assert mode(path) == 0o640


def test_chmod_a_directory_without_directory_permissions(tmp_path):
    root = tmp_path / "root"
    path = write(root / "sub" / "file.txt")
    assert fileops.chmod_file_or_directory(str(root), 755)
    assert mode(root) == 0o755
    assert mode(root / "sub") == 0o755
    assert mode(path) == 0o755


def test_chmod_in_a_pretend_run(tmp_path):
    path = write(tmp_path / "file.txt")
    before = mode(path)
    assert fileops.chmod_file_or_directory(path, 600, pretend_run = True)
    assert mode(path) == before


def test_chmod_needs_an_existing_path(tmp_path):
    path = str(tmp_path / "missing")
    assert not fileops.chmod_file_or_directory(path, 600)
    with pytest.raises(SystemExit):
        fileops.chmod_file_or_directory(path, 600, exit_on_failure = True)


def test_chmod_reports_invalid_permissions(tmp_path):
    path = write(tmp_path / "file.txt")
    assert not fileops.chmod_file_or_directory(path, "rw")
    with pytest.raises(SystemExit):
        fileops.chmod_file_or_directory(path, "rw", exit_on_failure = True)


def test_mark_as_executable(tmp_path):
    path = write(tmp_path / "run.sh")
    os.chmod(path, 0o644)
    assert fileops.mark_as_executable(path, verbose = True)
    assert mode(path) & stat.S_IXUSR
    assert fileops.mark_as_executable(str(tmp_path / "missing"), pretend_run = True)


def test_mark_as_executable_needs_an_existing_path(tmp_path):
    path = str(tmp_path / "missing")
    assert not fileops.mark_as_executable(path)
    with pytest.raises(SystemExit):
        fileops.mark_as_executable(path, exit_on_failure = True)


def test_temporary_directory(tmp_path):
    ok, path = fileops.create_temporary_directory(verbose = True)
    try:
        assert ok and os.path.isdir(path)
    finally:
        os.rmdir(path)
    ok, path = fileops.create_temporary_directory(directory = str(tmp_path / "parent"))
    assert ok and os.path.dirname(path) == os.path.realpath(tmp_path / "parent")


def test_temporary_directory_in_a_pretend_run(tmp_path):
    # Pretend runs of the trim and batch tools carry on with the planned path
    ok, path = fileops.create_temporary_directory(directory = str(tmp_path), pretend_run = True)
    assert ok
    assert os.path.dirname(path) == str(tmp_path)
    assert os.listdir(tmp_path) == []


def test_temporary_directory_reports_a_failure(monkeypatch):
    monkeypatch.setattr(fileops.tempfile, "mkdtemp", lambda **kwargs: "/nonexistent/joybox")
    assert fileops.create_temporary_directory() == (False, "Unable to create temporary directory")


def test_temporary_file():
    ok, path = fileops.create_temporary_file(suffix = ".txt", prefix = "joybox", verbose = True)
    try:
        assert ok and os.path.isfile(path)
        assert os.path.basename(path).startswith("joybox")
        assert path.endswith(".txt")
    finally:
        os.remove(path)


def test_temporary_file_in_a_pretend_run():
    ok, path = fileops.create_temporary_file(suffix = ".txt", pretend_run = True)
    assert ok and path.endswith(".txt")
    assert not os.path.exists(path)


def test_temporary_file_reports_a_failure(monkeypatch):
    class Vanishing:
        name = "/nonexistent/joybox.txt"
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
    monkeypatch.setattr(fileops.tempfile, "NamedTemporaryFile", lambda **kwargs: Vanishing())
    assert fileops.create_temporary_file() == (False, "Unable to create temporary file")


###########################################################
# Symlinks
###########################################################

def test_symlink_creates_its_parent(tmp_path):
    target = write(tmp_path / "target.txt")
    link = str(tmp_path / "a" / "link.txt")
    assert fileops.create_symlink(target, link, verbose = True)
    assert os.readlink(link) == target


@pytest.mark.parametrize("existing", ["file", "directory", "link"])
def test_symlink_replaces_what_is_there(tmp_path, existing):
    target = write(tmp_path / "target.txt")
    link = tmp_path / "link"
    if existing == "file":
        write(link)
    elif existing == "directory":
        write(link / "inner.txt")
    else:
        os.symlink(tmp_path / "elsewhere", link)
    assert fileops.create_symlink(target, str(link))
    assert os.readlink(link) == target


def test_symlink_without_overwrite_refuses_an_existing_path(tmp_path):
    target = write(tmp_path / "target.txt")
    link = write(tmp_path / "link")
    assert not fileops.create_symlink(target, link, overwrite = False)
    with pytest.raises(SystemExit):
        fileops.create_symlink(target, link, overwrite = False, exit_on_failure = True)


def test_symlink_relative_to_a_working_directory(tmp_path):
    write(tmp_path / "dir" / "target.txt")
    before = os.getcwd()
    assert fileops.create_symlink("target.txt", "link.txt", cwd = str(tmp_path / "dir"), make_parent = False)
    assert os.getcwd() == before
    assert read(tmp_path / "dir" / "link.txt") == "x"


def test_symlink_restores_the_working_directory_after_a_failure(tmp_path):
    before = os.getcwd()
    assert not fileops.create_symlink("a", "b", cwd = str(tmp_path / "missing"))
    assert os.getcwd() == before


def test_symlink_in_a_pretend_run(tmp_path):
    link = tmp_path / "link"
    assert fileops.create_symlink(str(tmp_path), str(link), pretend_run = True)
    assert not os.path.lexists(link)


def test_resolve_symlink(tmp_path):
    target = write(tmp_path / "target.txt")
    link = tmp_path / "link"
    os.symlink(target, link)
    assert fileops.resolve_symlink(str(link), verbose = True) == os.path.realpath(target)
    assert fileops.resolve_symlink(target) is None
    assert fileops.resolve_symlink(str(link), pretend_run = True) is None


def test_resolve_symlink_reports_a_failure(tmp_path, monkeypatch):
    link = tmp_path / "link"
    os.symlink(tmp_path, link)
    monkeypatch.setattr(os.path, "realpath", fail)
    assert fileops.resolve_symlink(str(link)) is None
    with pytest.raises(SystemExit):
        fileops.resolve_symlink(str(link), exit_on_failure = True)
