# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import paths


###########################################################
# Filename decomposition
#
# paths is imported by 125 other modules, and the filename helpers decide where
# every ROM, asset and backup artifact lands. A change here moves files.
###########################################################

@pytest.mark.parametrize("path,expected", [
    ("a/b/file.txt", "file"),
    ("file.txt", "file"),
    ("noext", "noext"),
    (".hidden", ".hidden"),
])
def test_basename_strips_the_extension(path, expected):
    assert paths.get_filename_basename(path) == expected


@pytest.mark.parametrize("path,expected", [
    ("a/b/file.txt", ".txt"),
    ("noext", ""),
    (".hidden", ""),
])
def test_extension_is_extracted(path, expected):
    assert paths.get_filename_extension(path) == expected


@pytest.mark.parametrize("path,base,extension", [
    ("a/archive.tar.gz", "archive", ".tar.gz"),
    ("a/archive.tar.bz2", "archive", ".tar.bz2"),
])
def test_tarball_extensions_are_treated_as_one_unit(path, base, extension):

    # pathlib would call these ".gz" and ".bz2", splitting "archive.tar" off as
    # the stem. Archive handling depends on seeing the whole compound suffix.
    assert paths.get_filename_basename(path) == base
    assert paths.get_filename_extension(path) == extension


@pytest.mark.parametrize("path,expected", [
    ("dir/file.txt", ["dir/file", ".txt"]),
    ("archive.tar.gz", ["archive", ".tar.gz"]),
    ("noextension", ["noextension", ""]),
    ("file.", ["file.", ""]),
])
def test_split_keeps_the_remainder(path, expected):

    # Regression: the remainder was computed as path[:-len(ext)], and for an
    # extensionless name len(ext) is 0 - so path[:-0] is path[:0], and the whole
    # filename was silently dropped.
    assert paths.get_filename_split(path) == expected


def test_split_round_trips():
    for path in ["dir/file.txt", "archive.tar.gz", "noextension", ".hidden"]:
        remainder, extension = paths.get_filename_split(path)
        assert remainder + extension == path


def test_filename_file_drops_the_directory():
    assert paths.get_filename_file("a/b/file.txt") == "file.txt"
    assert paths.get_filename_file("a/archive.tar.gz") == "archive.tar.gz"


def test_filename_directory_is_the_parent():
    assert paths.get_filename_directory("a/b/file.txt") == os.path.join("a", "b")


###########################################################
# Extension replacement
###########################################################

@pytest.mark.parametrize("path,extension,expected", [
    ("dir/file.txt", ".md", os.path.join("dir", "file.md")),
    ("file.txt", ".md", "file.md"),
    ("a/archive.tar.gz", ".zip", os.path.join("a", "archive.zip")),
])
def test_extension_is_replaced_not_appended(path, extension, expected):
    assert paths.change_filename_extension(path, extension) == expected


def test_replacing_the_extension_of_a_tarball_drops_the_whole_suffix():

    # ".tar.gz" -> ".zip", not "archive.tar.zip". Getting this wrong produces a
    # file whose name claims two incompatible formats.
    assert paths.change_filename_extension("archive.tar.gz", ".zip") == "archive.zip"


###########################################################
# Joining
###########################################################

def test_join_normalizes():
    assert paths.join_paths("a", "b", "c.txt") == os.path.join("a", "b", "c.txt")


def test_join_rejects_types_it_cannot_resolve():

    # Raising beats silently stringifying: a path built from an unexpected type
    # would point somewhere plausible but wrong.
    with pytest.raises(TypeError):
        paths.join_paths("a", 5)


###########################################################
# Rebasing
###########################################################

def test_rebase_moves_a_path_between_roots():
    assert paths.rebase_file_path("/old/base/file.txt", "/old/base", "/new/base") == \
        os.path.normpath("/new/base/file.txt")


def test_rebase_leaves_unrelated_paths_alone():
    assert paths.rebase_file_path("/other/file.txt", "/old/base", "/new/base") == \
        os.path.normpath("/other/file.txt")


def test_rebase_applies_to_a_whole_list():
    rebased = paths.rebase_file_paths(
        ["/old/a.txt", "/old/b.txt"], "/old", "/new")

    assert rebased == [os.path.normpath("/new/a.txt"), os.path.normpath("/new/b.txt")]


###########################################################
# Relative and absolute conversion
###########################################################

def test_paths_are_made_relative_to_a_base():
    assert paths.convert_file_list_to_relative_paths(
        ["/base/a.txt", "/base/sub/b.txt"], "/base") == ["a.txt", "sub/b.txt"]


def test_paths_are_made_absolute_against_a_base():
    assert paths.convert_file_list_to_absolute_paths(
        ["a.txt", "sub/b.txt"], "/base") == ["/base/a.txt", "/base/sub/b.txt"]


###########################################################
# Grouping
###########################################################

def test_files_group_by_their_directory():
    grouped = paths.group_files_by_directory(
        [os.path.join("a", "one.txt"), os.path.join("a", "two.txt"), os.path.join("b", "three.txt")])

    assert sorted(grouped) == ["a", "b"]
    assert len(grouped["a"]) == 2


def test_files_group_by_path_depth():
    grouped = paths.group_files_by_path_depth(
        [os.path.join("roms", "snes", "game.sfc"), os.path.join("roms", "nes", "game.nes")],
        depth = 2)

    assert sorted(grouped) == [os.path.join("roms", "nes"), os.path.join("roms", "snes")]


def test_shallow_paths_fall_back_to_the_fallback_key():
    grouped = paths.group_files_by_path_depth(["loose.txt"], depth = 2, fallback_key = "Other")

    assert "Other" in grouped


###########################################################
# Exclusion
###########################################################

def test_an_excluded_component_matches_anywhere_in_the_path():
    assert paths.is_exclude_path(os.path.join("a", "node_modules", "x.js"), ["node_modules"]) is True


def test_a_path_without_the_excluded_component_is_kept():
    assert paths.is_exclude_path(os.path.join("a", "b", "c.js"), ["node_modules"]) is False


def test_no_excludes_keeps_everything():
    assert paths.is_exclude_path(os.path.join("a", "b.js"), []) is False


def test_prune_drops_paths_under_an_excluded_prefix():
    pruned = paths.prune_paths(["/keep/a", "/drop/b", "/keep/c"], ["/drop"])

    assert pruned == ["/keep/a", "/keep/c"]


###########################################################
# Parent relationships
###########################################################

def test_a_directory_is_the_parent_of_its_contents():
    assert paths.is_parent_path("/a", "/a/b/c.txt") is True


def test_a_sibling_is_not_a_parent():
    assert paths.is_parent_path("/a", "/b/c.txt") is False


def test_a_path_is_its_own_parent():

    # is_relative_to is reflexive, and prune_child_paths relies on that to
    # collapse an exact duplicate.
    assert paths.is_parent_path("/a", "/a") is True


###########################################################
# Drive letters
###########################################################

@pytest.mark.parametrize("candidate,expected", [
    ("C", True),
    ("z", True),
    ("", False),
    ("1", False),
    (None, False),
])
def test_drive_letter_validation(candidate, expected):
    assert paths.is_drive_letter_valid(candidate) is expected


###########################################################
# Invalid characters
###########################################################

def test_control_characters_are_stripped():
    assert "\x00" not in paths.replace_invalid_path_characters("bad\x00name")


def test_trailing_dots_and_spaces_are_trimmed():

    # Windows silently rejects these, so a name that survives here would fail
    # only once the collection is synced to a Windows machine.
    assert paths.replace_invalid_path_characters("name. ") == "name"


def test_runs_of_spaces_collapse():
    assert paths.replace_invalid_path_characters("a    b") == "a b"
