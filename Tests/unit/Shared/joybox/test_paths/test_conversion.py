# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox import paths
from paths_helpers import write


###########################################################
# Top level paths
###########################################################

def test_top_level_paths_are_the_first_components():
    listed = paths.convert_to_top_level_paths(["Disc 1/game.bin", "Disc 1/game.cue", "Manual.pdf", "C:/Extras/art.png"])
    assert listed == ["Disc 1", "Extras", "Manual.pdf"]


def test_top_level_paths_can_be_filtered_by_type(tmp_path):
    write(tmp_path / "Disc 1" / "game.bin")
    write(tmp_path / "Manual.pdf")
    listed = ["Disc 1/game.bin", "Manual.pdf"]
    assert paths.convert_to_top_level_paths(listed, path_root = str(tmp_path), only_files = True) == ["Manual.pdf"]
    assert paths.convert_to_top_level_paths(listed, path_root = str(tmp_path), only_dirs = True) == ["Disc 1"]


def test_top_level_paths_under_a_root_without_a_filter_keep_everything(tmp_path):
    listed = ["Disc 1/game.bin", "Manual.pdf"]
    assert paths.convert_to_top_level_paths(listed, path_root = str(tmp_path)) == ["Disc 1", "Manual.pdf"]


###########################################################
# Relative conversion
###########################################################

def test_relative_conversion_strips_only_the_leading_base():
    assert paths.convert_file_list_to_relative_paths(["/g/a/g/b"], "/g") == ["a/g/b"]
    assert paths.convert_file_list_to_relative_paths(["/g/a"], "/g/") == ["a"]
    assert paths.convert_file_list_to_relative_paths(["/other/a"], "/g") == ["/other/a"]


###########################################################
# Normalizing and splitting
###########################################################

@pytest.mark.parametrize("path,kwargs,expected", [
    ("a/./b/../c", {}, "a/c"),
    ("a\\b\\c", {}, "a/b/c"),
    ("a//b/", {"force_posix": True}, "a/b"),
    ("a/b/../c", {"force_windows": True}, "a/c"),
    ("a/b", {"separator": "\\"}, "a/b"),
    ("a\\b", {"separator": "|"}, "a|b"),
])
def test_normalize(path, kwargs, expected):
    assert paths.normalize_file_path(path, **kwargs) == expected


def test_split_drops_the_drive_from_later_parts():
    assert paths.split_file_path("C:/Games/a.exe;C:/Games/b.exe", ";") == ["C:/Games/a.exe", "Games/b.exe"]


###########################################################
# Rebasing
###########################################################

@pytest.mark.parametrize("path,old,new,expected", [
    ("/mnt/Locker/Games/x", "/mnt/Locker", "", "Games/x"),
    ("/mnt/Locker/Games/x", "/mnt/Locker/", "/local", "/local/Games/x"),
    ("/mnt/Locker", "/mnt/Locker", "/local", "/local"),
    ("/mnt/Locker", "/mnt/Locker", "", "."),
    # Only a whole leading component moves, and only once
    ("/mnt/Locker2/Games/x", "/mnt/Locker", "", "/mnt/Locker2/Games/x"),
    ("/home/mnt/Locker/x", "/mnt/Locker", "/local", "/home/mnt/Locker/x"),
    ("/mnt/Locker/Backup/mnt/Locker/x", "/mnt/Locker", "/local", "/local/Backup/mnt/Locker/x"),
    ("/a/b", "/", "/root", "/root/a/b"),
])
def test_rebase(path, old, new, expected):
    assert paths.rebase_file_path(path, old, new) == expected


def test_rebase_many():
    assert paths.rebase_file_paths(["/a/x", "/a/y"], "/a", "/b") == ["/b/x", "/b/y"]


def test_front_slice_drops_the_first_component():
    assert paths.get_filename_front_slice("Disc 1/game.bin") == "game.bin"
    assert paths.get_filename_front_slice("Disc 1/sub/game.bin") == "sub/game.bin"


###########################################################
# Joining
###########################################################

def test_join_accepts_enums():
    joined = paths.join_paths("/games", config.Supercategory.ROMS, "a/../b")
    assert joined == os.path.join("/games", config.Supercategory.ROMS.val(), "b")


def test_join_refuses_other_types():
    with pytest.raises(TypeError):
        paths.join_paths("/games", 42)


###########################################################
# Anchors and drives
###########################################################

@pytest.mark.parametrize("path,anchor,drive,offset", [
    ("/games/rom.iso", "/", "/", "games/rom.iso"),
    ("C:\\Games\\rom.iso", "C:\\", "c", "Games\\rom.iso"),
    ("D:/Games/rom.iso", "D:\\", "d", "Games/rom.iso"),
    ("games/rom.iso", "", "", "games/rom.iso"),
])
def test_anchor_drive_and_offset(path, anchor, drive, offset):
    assert paths.get_filename_anchor(path) == anchor
    assert paths.get_filename_drive(path) == drive
    assert paths.get_filename_drive_offset(path) == offset
    assert paths.get_directory_anchor(path) == anchor
    assert paths.get_directory_drive(path) == drive
    assert paths.get_directory_drive_offset(path) == offset


def test_directory_parts():
    assert paths.get_directory_parts("/games/roms") == ["/", "games", "roms"]
    assert paths.get_filename_parts("games/rom.iso") == ["games", "rom.iso"]


def test_changing_the_extension_of_a_bare_name():
    assert paths.change_filename_extension("rom.iso", ".chd") == "rom.chd"
