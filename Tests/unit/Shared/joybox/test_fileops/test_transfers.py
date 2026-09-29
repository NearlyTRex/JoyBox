# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import fileops
from fileops_helpers import write, read, tree, fail, mode


###########################################################
# Copy and move
###########################################################

def test_copy_a_file(tmp_path):
    src = write(tmp_path / "src.txt", "data")
    dest = str(tmp_path / "dest.txt")
    assert fileops.copy_file_or_directory(src, dest, verbose = True)
    assert read(dest) == "data"
    assert os.path.exists(src)


def test_copy_a_directory_merges_into_the_destination(tmp_path):
    write(tmp_path / "src" / "a.txt")
    write(tmp_path / "src" / "sub" / "b.txt")
    write(tmp_path / "dest" / "kept.txt")
    assert fileops.copy_file_or_directory(str(tmp_path / "src"), str(tmp_path / "dest"))
    assert tree(tmp_path / "dest") == {"a.txt", "sub", os.path.join("sub", "b.txt"), "kept.txt"}


def test_copy_excludes_matching_names(tmp_path):
    write(tmp_path / "src" / "keep.txt")
    write(tmp_path / "src" / "skip.log")
    write(tmp_path / "src" / ".git" / "HEAD")
    assert fileops.copy_file_or_directory(str(tmp_path / "src"), str(tmp_path / "dest"), excludes = ["*.log", ".git"])
    assert tree(tmp_path / "dest") == {"keep.txt"}


def test_copy_an_excluded_file_is_a_quiet_no_op(tmp_path):
    src = write(tmp_path / "skip.log")
    dest = tmp_path / "dest.log"
    assert fileops.copy_file_or_directory(src, str(dest), excludes = ["*.log"])
    assert not dest.exists()


def test_copy_skips_an_existing_destination(tmp_path):
    src = write(tmp_path / "src.txt", "new")
    dest = write(tmp_path / "dest.txt", "old")
    assert fileops.copy_file_or_directory(src, dest, skip_existing = True, verbose = True)
    assert read(dest) == "old"


def test_copy_skips_an_identical_destination(tmp_path, monkeypatch):
    src = write(tmp_path / "src.txt", "same")
    dest = write(tmp_path / "dest.txt", "same")
    monkeypatch.setattr(fileops.shutil, "copy", fail)
    assert fileops.copy_file_or_directory(src, dest, skip_identical = True, verbose = True)


def test_copy_replaces_a_different_destination_when_skipping_identical(tmp_path):
    src = write(tmp_path / "src.txt", "new")
    dest = write(tmp_path / "dest.txt", "old")
    assert fileops.copy_file_or_directory(src, dest, skip_identical = True)
    assert read(dest) == "new"


def test_copy_in_a_pretend_run(tmp_path):
    src = write(tmp_path / "src.txt")
    dest = tmp_path / "dest.txt"
    assert fileops.copy_file_or_directory(src, str(dest), pretend_run = True)
    assert not dest.exists()


def test_copy_failure_is_logged_when_skipping_errors(tmp_path):
    log = tmp_path / "errors.txt"
    src = str(tmp_path / "missing.txt")
    assert not fileops.copy_file_or_directory(src, str(tmp_path / "dest.txt"), skip_on_error = True, error_log_path = str(log))
    assert read(log) == src + "\n"


def test_copy_failure_exits_when_asked(tmp_path):
    src = str(tmp_path / "missing.txt")
    assert not fileops.copy_file_or_directory(src, str(tmp_path / "dest.txt"))
    with pytest.raises(SystemExit):
        fileops.copy_file_or_directory(src, str(tmp_path / "dest.txt"), exit_on_failure = True)


def test_move_a_file(tmp_path):
    src = write(tmp_path / "src.txt", "data")
    dest = str(tmp_path / "dest.txt")
    assert fileops.move_file_or_directory(src, dest, verbose = True)
    assert read(dest) == "data"
    assert not os.path.exists(src)


def test_move_skips_existing_and_identical_destinations(tmp_path):
    src = write(tmp_path / "src.txt", "same")
    dest = write(tmp_path / "dest.txt", "same")
    assert fileops.move_file_or_directory(src, dest, skip_existing = True)
    assert fileops.move_file_or_directory(src, dest, skip_identical = True)
    assert os.path.exists(src)


def test_move_in_a_pretend_run(tmp_path):
    src = write(tmp_path / "src.txt")
    assert fileops.move_file_or_directory(src, str(tmp_path / "dest.txt"), pretend_run = True)
    assert os.path.exists(src)


def test_move_failure(tmp_path):
    src = str(tmp_path / "missing.txt")
    dest = str(tmp_path / "dest.txt")
    log = tmp_path / "errors.txt"
    assert not fileops.move_file_or_directory(src, dest)
    assert not fileops.move_file_or_directory(src, dest, skip_on_error = True, error_log_path = str(log))
    assert read(log) == src + "\n"
    with pytest.raises(SystemExit):
        fileops.move_file_or_directory(src, dest, exit_on_failure = True)


###########################################################
# Transfer
###########################################################

def test_transfer_copies_contents_and_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(fileops.config, "transfer_chunk_size", 3)
    src = write(tmp_path / "src.bin", "0123456789")
    os.chmod(src, 0o750)
    dest = str(tmp_path / "dest.bin")
    assert fileops.transfer_file(src, dest, verbose = True)
    assert read(dest) == "0123456789"
    assert mode(dest) == 0o750
    assert os.path.exists(src)


def test_transfer_can_delete_the_source(tmp_path):
    src = write(tmp_path / "src.bin")
    assert fileops.transfer_file(src, str(tmp_path / "dest.bin"), delete_afterwards = True)
    assert not os.path.exists(src)


def test_transfer_reports_progress_and_closes_the_bar(tmp_path, monkeypatch):
    import tqdm
    bars = []
    class RecordingBar:
        def __init__(self, total):
            self.total = total
            self.updates = []
            self.closed = False
            bars.append(self)
        def update(self, count):
            self.updates.append(count)
        def close(self):
            self.closed = True
    monkeypatch.setattr(tqdm, "tqdm", RecordingBar)
    monkeypatch.setattr(fileops.config, "transfer_chunk_size", 4)
    src = write(tmp_path / "src.bin", "0123456789")
    assert fileops.transfer_file(src, str(tmp_path / "dest.bin"), show_progress = True)
    assert bars[0].total == 10
    assert bars[0].updates == [4, 4, 2]
    assert bars[0].closed


def test_transfer_onto_itself_is_a_no_op(tmp_path):
    src = write(tmp_path / "src.bin", "data")
    assert fileops.transfer_file(src, src)
    assert read(src) == "data"


def test_transfer_skips_existing_and_identical_destinations(tmp_path):
    src = write(tmp_path / "src.bin", "same")
    dest = write(tmp_path / "dest.bin", "same")
    assert fileops.transfer_file(src, dest, skip_existing = True)
    assert fileops.transfer_file(src, dest, skip_identical = True, delete_afterwards = True)
    assert os.path.exists(src)


def test_transfer_in_a_pretend_run(tmp_path):
    src = write(tmp_path / "src.bin")
    dest = tmp_path / "dest.bin"
    assert fileops.transfer_file(src, str(dest), delete_afterwards = True, pretend_run = True)
    assert not dest.exists()
    assert os.path.exists(src)


def test_transfer_failure(tmp_path):
    src = str(tmp_path / "missing.bin")
    dest = str(tmp_path / "dest.bin")
    log = tmp_path / "errors.txt"
    assert not fileops.transfer_file(src, dest)
    assert not fileops.transfer_file(src, dest, skip_on_error = True, error_log_path = str(log))
    assert read(log) == src + "\n"
    with pytest.raises(SystemExit):
        fileops.transfer_file(src, dest, exit_on_failure = True)


def test_transfer_removes_a_partial_destination(tmp_path, monkeypatch):
    src = write(tmp_path / "src.bin")
    dest = tmp_path / "dest.bin"
    monkeypatch.setattr(fileops.shutil, "copymode", fail)
    assert not fileops.transfer_file(src, str(dest), skip_on_error = True)
    assert not dest.exists()
