# Imports
import os
import sys
import time

# Third-party imports
import pytest

# Local imports
from joybox import paths
from paths_helpers import write


###########################################################
# Existence
###########################################################

def test_expand_path_resolves_home_and_variables(monkeypatch):
    monkeypatch.setenv("HOME", "/home/player")
    monkeypatch.setenv("GAMES", "roms")
    assert paths.expand_path("~/$GAMES") == "/home/player/roms"


def test_existence_is_case_sensitive_by_default(tmp_path):
    write(tmp_path / "Game.iso")
    assert paths.does_path_exist(str(tmp_path / "Game.iso"))
    assert not paths.does_path_exist(str(tmp_path / "game.iso"))
    assert not paths.does_path_exist("")
    assert not paths.does_path_exist(None)


def test_existence_can_ignore_case(tmp_path):
    write(tmp_path / "Game.iso")
    assert paths.does_path_exist(str(tmp_path / "GAME.ISO"), case_sensitive_paths = False)
    assert not paths.does_path_exist(str(tmp_path / "Other.iso"), case_sensitive_paths = False)


def test_ignoring_case_in_a_missing_directory_is_not_an_error(tmp_path):
    assert not paths.does_path_exist(str(tmp_path / "missing" / "game.iso"), case_sensitive_paths = False)


def test_existence_can_match_a_name_prefix(tmp_path):
    write(tmp_path / "Game (Disc 1).iso")
    assert paths.does_path_exist(str(tmp_path / "Game"), case_sensitive_paths = False, partial_paths = True)
    assert not paths.does_path_exist(str(tmp_path / "Other"), case_sensitive_paths = False, partial_paths = True)
    assert not paths.does_path_exist(str(tmp_path / "missing" / "Game"), case_sensitive_paths = False, partial_paths = True)


def test_paths_are_equal_through_symlinks(tmp_path):
    target = write(tmp_path / "target")
    os.symlink(target, tmp_path / "link")
    assert paths.are_paths_equal(target, str(tmp_path / "link"))
    assert not paths.are_paths_equal(target, str(tmp_path))
    assert not paths.are_paths_equal(target, "")


def test_type_checks(tmp_path):
    path = write(tmp_path / "file")
    os.symlink(tmp_path, tmp_path / "dir_link")
    os.symlink(path, tmp_path / "file_link")
    assert paths.is_path_file(path)
    assert not paths.is_path_file(str(tmp_path))
    assert paths.is_path_directory(str(tmp_path))
    assert not paths.is_path_directory(path)
    assert paths.is_path_file_or_directory(path)
    assert paths.is_path_file_or_directory(str(tmp_path))
    assert not paths.is_path_file_or_directory(str(tmp_path / "dir_link"))
    assert paths.is_path_symlink(str(tmp_path / "file_link"))
    assert not paths.is_path_symlink(path)


@pytest.mark.parametrize("check", [
    paths.is_path_file,
    paths.is_path_directory,
    paths.is_path_symlink,
    paths.is_path_file_or_directory,
])
def test_type_checks_refuse_missing_and_invalid_paths(tmp_path, check):
    assert not check(str(tmp_path / "missing"))
    assert not check(None)
    assert not check("")


def test_a_dangling_symlink_is_still_a_symlink(tmp_path):
    os.symlink(tmp_path / "missing", tmp_path / "dangling")
    assert paths.is_path_symlink(str(tmp_path / "dangling"))


###########################################################
# Validity
###########################################################

@pytest.mark.parametrize("candidate", [None, "", 42, "a\0b", "x" * 5000, "a/" + "y" * 300])
def test_invalid_paths(candidate):
    assert paths.is_path_valid(candidate) is False


@pytest.mark.parametrize("candidate", ["relative/file.txt", "/absolute/missing/file.txt", "/"])
def test_valid_paths_need_not_exist(candidate):
    assert paths.is_path_valid(candidate) is True


def test_validity_on_windows_uses_the_drive(monkeypatch):
    monkeypatch.setattr(paths.os, "name", "nt")
    monkeypatch.setenv("SystemDrive", "/")
    assert paths.is_path_valid("C:/Games/game.exe") is True
    monkeypatch.setenv("SystemDrive", "/nonexistent")
    assert paths.is_path_valid("C:/Games/game.exe") is True


###########################################################
# Directory info
###########################################################

def test_directory_contents(tmp_path):
    write(tmp_path / "b.txt")
    write(tmp_path / "a.txt")
    write(tmp_path / "skip.log")
    assert paths.get_directory_contents(str(tmp_path), excludes = ["skip"]) == ["a.txt", "b.txt"]
    assert paths.get_directory_contents(str(tmp_path / "a.txt")) == []
    assert paths.get_directory_contents(str(tmp_path / "missing")) == []


def test_directory_emptiness_and_files(tmp_path):
    os.makedirs(tmp_path / "empty")
    write(tmp_path / "nested" / "deep" / "rom.iso")
    assert paths.is_directory_empty(str(tmp_path / "empty"))
    assert not paths.does_directory_contain_files(str(tmp_path / "empty"))
    assert paths.does_directory_contain_files(str(tmp_path / "nested"))
    assert not paths.does_directory_contain_files(str(tmp_path / "nested"), recursive = False)
    assert paths.does_directory_contain_files(str(tmp_path / "nested" / "deep"), recursive = False)


def test_directory_files_by_extension(tmp_path):
    write(tmp_path / "top.txt")
    write(tmp_path / "sub" / "rom.ISO")
    assert paths.does_directory_contain_files_by_extensions(str(tmp_path), [".iso"])
    assert not paths.does_directory_contain_files_by_extensions(str(tmp_path), [".zip"])
    assert paths.does_directory_contain_files_by_extensions(str(tmp_path), [".txt"], recursive = False)
    assert not paths.does_directory_contain_files_by_extensions(str(tmp_path), [".iso"], recursive = False)


def test_directory_symlink_dirs(tmp_path):
    os.makedirs(tmp_path / "root" / "real")
    assert not paths.does_directory_contain_symlink_dirs(str(tmp_path / "root"))
    os.symlink(tmp_path / "root" / "real", tmp_path / "root" / "link")
    assert paths.does_directory_contain_symlink_dirs(str(tmp_path / "root"))


def test_directory_size_counts_file_bytes_only(tmp_path):
    write(tmp_path / "a", "12345")
    write(tmp_path / "sub" / "b", "123")
    os.symlink(tmp_path / "missing", tmp_path / "dangling")
    assert paths.get_directory_size(str(tmp_path)) == 8


def test_directory_info(tmp_path):
    write(tmp_path / "game" / "rom.iso", "1234")
    info = paths.get_directory_info(str(tmp_path / "game"))
    assert info["name"] == "game"
    assert info["parent"] == str(tmp_path)
    assert info["front"] == "/"
    assert info["size"] == 4
    assert info["contents"] == ["rom.iso"]
    assert info["anchor"] == "/"
    assert info["drive"] == "/"
    assert info["drive_offset"] == str(tmp_path / "game")[1:]
    assert info["is_empty"] is False
    assert info["has_files"] is True


def test_directory_front_of_nothing():
    assert paths.get_directory_front("") == ""
    assert paths.get_filename_front("") == ""


###########################################################
# File info
###########################################################

def test_file_info(tmp_path):
    path = write(tmp_path / "Game.tar.gz", "123")
    info = paths.get_filename_info(path)
    assert info["file_base"] == "Game"
    assert info["file_ext"] == ".tar.gz"
    assert info["file"] == "Game.tar.gz"
    assert info["dir"] == str(tmp_path)
    assert info["size"] == 3
    assert info["file_anchor"] == "/"
    assert info["file_drive"] == "/"
    assert isinstance(info["mime"], str)


def test_mime_type_without_libmagic(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "magic", None)
    assert paths.get_file_mime_type(write(tmp_path / "file")) == ""


def test_file_age(tmp_path):
    path = write(tmp_path / "file")
    hour_ago = time.time() - 3600
    os.utime(path, (hour_ago, hour_ago))
    assert paths.get_file_age_in_hours(path) == pytest.approx(1.0, abs = 0.01)
    assert paths.get_file_mod_time(path) == int(hour_ago)


def test_file_age_of_a_missing_file(tmp_path):
    assert paths.get_file_age_in_hours(str(tmp_path / "missing")) == float("inf")
    assert paths.get_file_mod_time(str(tmp_path / "missing")) == 0


def test_an_invalid_path_is_no_ones_parent():
    assert paths.is_parent_path("/games", "/games/a\0b") is False


def test_validity_on_windows_keeps_an_existing_drive(monkeypatch):
    monkeypatch.setattr(paths.os, "name", "nt")
    monkeypatch.setattr(paths.os.path, "splitdrive", lambda path: ("/", path))
    assert paths.is_path_valid("Games/game.exe") is True


def test_an_invalid_name_reported_by_windows_is_not_valid(monkeypatch):
    def lstat(path):
        error = OSError(22, "The filename, directory name, or volume label syntax is incorrect")
        error.winerror = 123
        raise error

    monkeypatch.setattr(paths.os, "lstat", lstat)
    assert paths.is_path_valid("C:/Games/bad?name.exe") is False
