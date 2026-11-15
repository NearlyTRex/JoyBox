# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import fileops
from file_helpers import write
from fileops_helpers import read, tree, fail


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


def test_fileio_error_survives_an_unwritable_log(tmp_path, monkeypatch):
    warnings = []
    monkeypatch.setattr(fileops.logger, "log_warning", warnings.append)

    fileops.report_fileio_error("src.bin", None, str(tmp_path / "missing" / "errors.txt"))

    assert warnings[0] == "Skipping file after I/O error: 'src.bin'"
    assert warnings[1].startswith("Unable to write error log")


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


def sjis_name(text):
    # How a utf-8 filesystem hands back a name that was written as Shift-JIS bytes.
    return os.fsdecode(text.encode("cp932"))


def test_decoding_renames_legacy_files_and_directories(tmp_path):
    write(tmp_path / sjis_name("顔") / sjis_name("主人公1.png"))
    assert fileops.decode_legacy_filenames(str(tmp_path), "cp932", verbose = True)
    assert tree(tmp_path) == {"顔", os.path.join("顔", "主人公1.png")}


def test_decoding_leaves_utf8_names_alone(tmp_path):
    # Names that are already utf-8 are valid cp932 too often enough to be mangled.
    write(tmp_path / "主人公.png")
    write(tmp_path / "plain.txt")
    assert fileops.decode_legacy_filenames(str(tmp_path), "cp932")
    assert tree(tmp_path) == {"主人公.png", "plain.txt"}


def test_decoding_leaves_names_the_encoding_cannot_read(tmp_path):
    undecodable = os.fsdecode(b"\x81\x20.bin")
    write(tmp_path / undecodable)
    assert fileops.decode_legacy_filenames(str(tmp_path), "cp932")
    assert tree(tmp_path) == {undecodable}


def test_decoding_does_not_overwrite_an_existing_name(tmp_path):
    write(tmp_path / sjis_name("顔.png"), "legacy")
    write(tmp_path / "顔.png", "current")
    assert fileops.decode_legacy_filenames(str(tmp_path), "cp932")
    assert read(tmp_path / "顔.png") == "current"
    assert sjis_name("顔.png") in os.listdir(tmp_path)


def split_at_backslash(text):
    # How an extractor that reads 0x5c as a separator writes a Shift-JIS name
    # whose second byte is 0x5c, as in 表 (0x95 0x5c).
    return [os.fsdecode(part) for part in text.encode("cp932").split(b"\\")]


def test_decoding_rejoins_a_name_split_at_a_backslash(tmp_path):
    write(tmp_path / "Picture" / os.path.join(*split_at_backslash("表示.png")))
    write(tmp_path / "Picture" / os.path.join(*split_at_backslash("表示２.png")))
    assert fileops.decode_legacy_filenames(str(tmp_path), "cp932", verbose = True)
    assert tree(tmp_path) == {"Picture", os.path.join("Picture", "表示.png"), os.path.join("Picture", "表示２.png")}


def test_decoding_rejoins_a_name_split_more_than_once(tmp_path):
    write(tmp_path / os.path.join(*split_at_backslash("表表.png")))
    assert fileops.decode_legacy_filenames(str(tmp_path), "cp932")
    assert tree(tmp_path) == {"表表.png"}


def test_decoding_rejoins_a_split_directory_name(tmp_path):
    write(tmp_path / os.path.join(*split_at_backslash("表示")) / "file.txt")
    assert fileops.decode_legacy_filenames(str(tmp_path), "cp932")
    assert tree(tmp_path) == {"表示", os.path.join("表示", "file.txt")}


def test_decoding_keeps_a_complete_directory_name_as_a_directory(tmp_path):
    write(tmp_path / sjis_name("顔") / "file.txt")
    assert fileops.decode_legacy_filenames(str(tmp_path), "cp932")
    assert tree(tmp_path) == {"顔", os.path.join("顔", "file.txt")}


def test_a_name_that_is_not_in_the_encoding_is_not_split():
    # 0x81 must be followed by a trail byte, and a space is not one, so the
    # name is broken partway through rather than cut short at its end.
    assert fileops.is_name_split_in_encoding(os.fsdecode(b"\x81 abc"), "cp932") is False


def test_decoding_keeps_a_split_name_whose_rejoined_name_exists(tmp_path):
    first, second = split_at_backslash("表示.png")
    write(tmp_path / first / second, "split")
    write(tmp_path / (first + "\\" + second), "whole")
    assert fileops.decode_legacy_filenames(str(tmp_path), "cp932")
    assert read(tmp_path / "表示.png") == "whole"
    assert os.path.isdir(tmp_path / first)


def test_decoding_in_a_pretend_run(tmp_path):
    write(tmp_path / sjis_name("顔.png"))
    first, second = split_at_backslash("表示.png")
    write(tmp_path / first / second)
    assert fileops.decode_legacy_filenames(str(tmp_path), "cp932", pretend_run = True)
    assert tree(tmp_path) == {sjis_name("顔.png"), first, os.path.join(first, second)}


def test_decoding_reports_a_failed_rename(tmp_path, monkeypatch):
    write(tmp_path / sjis_name("顔.png"))
    monkeypatch.setattr(os, "rename", fail)
    assert not fileops.decode_legacy_filenames(str(tmp_path), "cp932")
    with pytest.raises(SystemExit):
        fileops.decode_legacy_filenames(str(tmp_path), "cp932", exit_on_failure = True)


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
