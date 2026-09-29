# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import fileops
from fileops_helpers import write, read, tree, fail


###########################################################
# I/O error reporting
###########################################################

def test_fileio_error_removes_the_partial_destination_and_logs_the_source(tmp_path):
    dest = write(tmp_path / "dest.bin")
    log = str(tmp_path / "errors.txt")
    fileops.report_fileio_error("src.bin", dest, log)
    fileops.report_fileio_error("other.bin", None, log)
    assert not os.path.exists(dest)
    assert read(log) == "src.bin\nother.bin\n"


def test_fileio_error_keeps_the_destination_in_a_pretend_run(tmp_path):
    dest = write(tmp_path / "dest.bin")
    fileops.report_fileio_error("src.bin", dest, pretend_run = True)
    assert os.path.exists(dest)


def test_fileio_error_survives_an_unwritable_log(tmp_path):
    fileops.report_fileio_error("src.bin", None, str(tmp_path / "missing" / "errors.txt"))


###########################################################
# Header checks
###########################################################

@pytest.mark.parametrize("header,expected", [
    (b"PK\x03\x04", True),
    ("PK", True),
    (b"7z", False),
])
def test_header_is_compared_as_bytes(tmp_path, header, expected):
    path = tmp_path / "archive.zip"
    path.write_bytes(b"PK\x03\x04rest")
    assert fileops.is_file_correctly_headered(str(path), header) is expected


def test_header_check_rejects_missing_files_and_directories(tmp_path):
    assert fileops.is_file_correctly_headered(str(tmp_path / "missing"), b"PK") is False
    assert fileops.is_file_correctly_headered(str(tmp_path), b"PK") is False


###########################################################
# File content modification
###########################################################

def test_replacements_apply_in_order(tmp_path):
    path = write(tmp_path / "config.ini", "root=$ROOT\nsave=$SAVE\n")
    assert fileops.replace_strings_in_file(path, [
        {"from": "$ROOT", "to": "/games"},
        {"from": "$SAVE", "to": "/games/saves"},
    ])
    assert read(path) == "root=/games\nsave=/games/saves\n"


def test_replacements_with_an_empty_side_are_skipped(tmp_path):
    # Launching swaps tokens in and back out, so an empty save dir must not
    # erase the token it would later need to restore.
    path = write(tmp_path / "config.ini", "save=$SAVE\n")
    assert fileops.replace_strings_in_file(path, [{"from": "$SAVE", "to": ""}, {"from": "", "to": "x"}])
    assert read(path) == "save=$SAVE\n"


def test_replacements_leave_the_file_alone_in_a_pretend_run(tmp_path):
    path = write(tmp_path / "config.ini", "a")
    assert fileops.replace_strings_in_file(path, [{"from": "a", "to": "b"}], verbose = True, pretend_run = True)
    assert read(path) == "a"


def test_replacements_need_a_file(tmp_path):
    assert not fileops.replace_strings_in_file(str(tmp_path), [], verbose = True)


def test_replacements_report_a_malformed_entry(tmp_path):
    path = write(tmp_path / "config.ini")
    assert not fileops.replace_strings_in_file(path, [{"from": "x"}])
    with pytest.raises(SystemExit):
        fileops.replace_strings_in_file(path, [{"from": "x"}], exit_on_failure = True)


def test_append_line_adds_a_missing_line(tmp_path):
    path = write(tmp_path / "list.txt", "one\n")
    assert fileops.append_line_to_file(path, "two", verbose = True)
    assert read(path) == "one\ntwo\n"


def test_append_line_does_not_duplicate(tmp_path):
    path = write(tmp_path / "list.txt", "one\ntwo\n")
    assert fileops.append_line_to_file(path, "one")
    assert read(path) == "one\ntwo\n"


def test_append_line_terminates_an_unfinished_last_line(tmp_path):
    path = write(tmp_path / "list.txt", "one")
    assert fileops.append_line_to_file(path, "two")
    assert read(path) == "one\ntwo\n"


def test_append_line_to_an_empty_file(tmp_path):
    path = write(tmp_path / "list.txt", "")
    assert fileops.append_line_to_file(path, "one")
    assert read(path) == "one\n"


def test_append_line_in_a_pretend_run(tmp_path):
    path = write(tmp_path / "list.txt", "one\n")
    assert fileops.append_line_to_file(path, "two", pretend_run = True)
    assert read(path) == "one\n"


def test_append_line_needs_a_file(tmp_path):
    assert not fileops.append_line_to_file(str(tmp_path / "missing"), "one", verbose = True)


def test_append_line_reports_undecodable_contents(tmp_path):
    path = tmp_path / "list.txt"
    path.write_bytes(b"\xff\xfe\xfa")
    assert not fileops.append_line_to_file(str(path), "one")
    with pytest.raises(SystemExit):
        fileops.append_line_to_file(str(path), "one", exit_on_failure = True)


def test_sort_orders_lines(tmp_path):
    path = write(tmp_path / "list.txt", "c\na\nb\n")
    assert fileops.sort_file_contents(path, verbose = True)
    assert read(path) == "a\nb\nc\n"


def test_sort_keeps_an_unterminated_last_line_separate(tmp_path):
    path = write(tmp_path / "list.txt", "b\na")
    assert fileops.sort_file_contents(path)
    assert read(path) == "a\nb\n"


def test_sort_in_a_pretend_run(tmp_path):
    path = write(tmp_path / "list.txt", "b\na\n")
    assert fileops.sort_file_contents(path, pretend_run = True)
    assert read(path) == "b\na\n"


def test_sort_needs_a_file(tmp_path):
    assert not fileops.sort_file_contents(str(tmp_path), verbose = True)


def test_sort_reports_undecodable_contents(tmp_path):
    path = tmp_path / "list.txt"
    path.write_bytes(b"\xff\xfe\xfa")
    assert not fileops.sort_file_contents(str(path))
    with pytest.raises(SystemExit):
        fileops.sort_file_contents(str(path), exit_on_failure = True)


###########################################################
# Directory modification
###########################################################

def test_empty_directories_are_removed(tmp_path):
    os.makedirs(tmp_path / "empty")
    write(tmp_path / "full" / "file.txt")
    assert fileops.remove_empty_directories(str(tmp_path))
    assert tree(tmp_path) == {"full", os.path.join("full", "file.txt")}


def test_empty_directory_removal_stops_at_a_failure(tmp_path, monkeypatch):
    os.makedirs(tmp_path / "empty")
    monkeypatch.setattr(fileops, "remove_directory", lambda **kwargs: False)
    assert not fileops.remove_empty_directories(str(tmp_path))


def test_symlinked_directories_become_real_directories(tmp_path):
    target = tmp_path / "target"
    write(target / "file.txt")
    root = tmp_path / "root"
    os.makedirs(root)
    os.symlink(target, root / "link")
    assert fileops.replace_symlinked_directories(str(root))
    assert not os.path.islink(root / "link")
    assert os.path.isdir(root / "link")
    assert os.path.exists(target / "file.txt")


@pytest.mark.parametrize("failing", ["remove_symlink", "make_directory"])
def test_symlinked_directory_replacement_stops_at_a_failure(tmp_path, monkeypatch, failing):
    os.makedirs(tmp_path / "target")
    os.makedirs(tmp_path / "root")
    os.symlink(tmp_path / "target", tmp_path / "root" / "link")
    monkeypatch.setattr(fileops, failing, lambda **kwargs: False)
    assert not fileops.replace_symlinked_directories(str(tmp_path / "root"))


def test_lowercasing_renames_files_and_directories(tmp_path):
    write(tmp_path / "Dir" / "Sub" / "File.TXT")
    write(tmp_path / "lower.txt")
    assert fileops.lowercase_all_paths(str(tmp_path), verbose = True)
    assert tree(tmp_path) == {"dir", os.path.join("dir", "sub"), os.path.join("dir", "sub", "file.txt"), "lower.txt"}


def test_lowercasing_in_a_pretend_run(tmp_path):
    write(tmp_path / "File.TXT")
    assert fileops.lowercase_all_paths(str(tmp_path), pretend_run = True)
    assert tree(tmp_path) == {"File.TXT"}


def test_lowercasing_reports_a_failed_rename(tmp_path, monkeypatch):
    write(tmp_path / "File.TXT")
    monkeypatch.setattr(os, "rename", fail)
    assert not fileops.lowercase_all_paths(str(tmp_path))
    with pytest.raises(SystemExit):
        fileops.lowercase_all_paths(str(tmp_path), exit_on_failure = True)


def test_sanitizing_filenames_honours_the_extension_filter(tmp_path):
    write(tmp_path / "Game: One.txt")
    write(tmp_path / "Game: Two.bin")
    os.makedirs(tmp_path / "Sub: Dir")
    assert fileops.sanitize_filenames(str(tmp_path), extension = ".txt")
    names = set(os.listdir(tmp_path))
    assert "Game: One.txt" not in names
    assert "Game: Two.bin" in names
    assert "Sub: Dir" in names


def test_sanitizing_filenames_stops_at_a_failed_move(tmp_path, monkeypatch):
    write(tmp_path / "Game: One.txt")
    monkeypatch.setattr(fileops, "move_file_or_directory", lambda **kwargs: False)
    assert not fileops.sanitize_filenames(str(tmp_path))
