# Imports
import os
import time
import pytest

# Local imports
from joybox import config, paths


###########################################################
# Path inspection and listing
#
# Nearly every module reaches for these. The predicates decide whether a game
# is installed or a backup is worth making, and the listers decide what gets
# hashed, synced and archived.
###########################################################

@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    for relative in ["game.zip", "docs/readme.txt", "docs/deep/notes.txt",
                     "logs/run.log"]:
        target = root / relative
        target.parent.mkdir(parents = True, exist_ok = True)
        target.write_text("content of %s\n" % relative)
    (root / "empty").mkdir()
    return root


def names(entries, root):
    return sorted(
        os.path.relpath(entry, str(root)).replace("\\", "/") for entry in entries)


###########################################################
# Validity and existence
###########################################################

@pytest.mark.parametrize("value", ["/some/path", "relative/path", "file.txt", "."])
def test_a_usable_path_is_valid(value):
    assert paths.is_path_valid(value) is True


@pytest.mark.parametrize("value", ["", None])
def test_an_unusable_path_is_not_valid(value):
    # Guards the joins, which raise on anything that is not a string.
    assert paths.is_path_valid(value) is False


def test_an_existing_file_exists(tree):
    assert paths.does_path_exist(str(tree / "game.zip")) is True


def test_a_missing_path_does_not_exist(tree):
    assert paths.does_path_exist(str(tree / "absent.zip")) is False


@pytest.mark.parametrize("value", ["", None])
def test_an_empty_path_does_not_exist(value):
    assert paths.does_path_exist(value) is False


def test_a_directory_exists(tree):
    assert paths.does_path_exist(str(tree / "docs")) is True


###########################################################
# Kind
###########################################################

def test_a_file_is_a_file(tree):
    assert paths.is_path_file(str(tree / "game.zip")) is True
    assert paths.is_path_directory(str(tree / "game.zip")) is False


def test_a_directory_is_a_directory(tree):
    assert paths.is_path_directory(str(tree / "docs")) is True
    assert paths.is_path_file(str(tree / "docs")) is False


@pytest.mark.parametrize("predicate", [
    "is_path_file", "is_path_directory", "is_path_file_or_directory"])
def test_a_missing_path_is_neither(tree, predicate):
    assert getattr(paths, predicate)(str(tree / "absent")) is False


@pytest.mark.parametrize("predicate", [
    "is_path_file", "is_path_directory", "is_path_file_or_directory", "is_path_symlink"])
def test_an_invalid_path_is_neither(predicate):
    assert getattr(paths, predicate)(None) is False


def test_either_kind_counts_as_file_or_directory(tree):
    assert paths.is_path_file_or_directory(str(tree / "game.zip")) is True
    assert paths.is_path_file_or_directory(str(tree / "docs")) is True


def test_a_symlink_is_recognised(tree):
    link = tree / "link.zip"
    link.symlink_to(tree / "game.zip")

    assert paths.is_path_symlink(str(link)) is True
    assert paths.is_path_symlink(str(tree / "game.zip")) is False


def test_a_symlink_to_a_file_is_still_a_file(tree):
    link = tree / "link.zip"
    link.symlink_to(tree / "game.zip")

    assert paths.is_path_file(str(link)) is True


###########################################################
# Comparison
###########################################################

def test_a_path_equals_itself(tree):
    assert paths.are_paths_equal(str(tree), str(tree)) is True


def test_two_different_paths_are_not_equal(tree):
    assert paths.are_paths_equal(str(tree / "docs"), str(tree / "logs")) is False


def test_a_path_equals_its_unnormalized_form(tree):
    messy = os.path.join(str(tree), "docs", "..", "docs")

    assert paths.are_paths_equal(str(tree / "docs"), messy) is True


def test_a_path_equals_its_symlink(tree):
    # realpath resolves both, which is what makes a linked locker comparable.
    link = tree / "docslink"
    link.symlink_to(tree / "docs")

    assert paths.are_paths_equal(str(tree / "docs"), str(link)) is True


@pytest.mark.parametrize("first,second", [(None, "/a"), ("/a", None), (None, None), ("", "")])
def test_a_missing_path_equals_nothing(first, second):
    assert paths.are_paths_equal(first, second) is False


def test_a_parent_contains_its_child(tree):
    assert paths.is_parent_path(str(tree), str(tree / "docs" / "readme.txt")) is True


def test_a_child_does_not_contain_its_parent(tree):
    assert paths.is_parent_path(str(tree / "docs"), str(tree)) is False


def test_a_sibling_is_not_a_parent(tree):
    assert paths.is_parent_path(str(tree / "docs"), str(tree / "logs")) is False


def test_a_path_is_its_own_parent(tree):
    assert paths.is_parent_path(str(tree), str(tree)) is True


###########################################################
# Expansion
###########################################################

def test_a_home_path_is_expanded(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    assert paths.expand_path("~/Locker") == os.path.join(str(tmp_path), "Locker")


def test_an_environment_variable_is_expanded(monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/expanded")

    assert paths.expand_path("$JOYBOX_TEST_ROOT/Locker") == "/expanded/Locker"


def test_an_unset_variable_is_left_alone():
    assert paths.expand_path("$JOYBOX_NOT_SET/Locker") == "$JOYBOX_NOT_SET/Locker"


def test_a_plain_path_is_unchanged():
    assert paths.expand_path("/absolute/path") == "/absolute/path"


###########################################################
# Listing files
###########################################################

def test_every_file_is_listed(tree):
    listed = paths.build_file_list(str(tree))

    assert names(listed, tree) == [
        "docs/deep/notes.txt", "docs/readme.txt", "game.zip", "logs/run.log"]


def test_directories_are_not_listed(tree):
    listed = paths.build_file_list(str(tree))

    assert not any(entry.endswith("empty") for entry in listed)


def test_relative_paths_are_available(tree):
    listed = paths.build_file_list(str(tree), use_relative_paths = True)

    assert all(not os.path.isabs(entry) for entry in listed)
    assert "game.zip" in listed


def test_an_empty_directory_lists_nothing(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    assert paths.build_file_list(str(empty)) == []


def test_a_missing_directory_lists_nothing(tmp_path):
    assert paths.build_file_list(str(tmp_path / "absent")) == []


def test_an_excluded_prefix_is_left_out(tree):
    # build_file_list excludes are path prefixes, not globs; the glob form is
    # matches_exclude_pattern, used by the leaf lister below.
    listed = paths.build_file_list(str(tree), excludes = [str(tree / "logs")])

    assert not any(entry.endswith(".log") for entry in listed)
    assert any(entry.endswith("game.zip") for entry in listed)


def test_a_glob_is_not_an_exclude_prefix(tree):
    listed = paths.build_file_list(str(tree), excludes = ["*.log"])

    assert any(entry.endswith(".log") for entry in listed)


def test_files_are_listed_by_extension(tree):
    listed = paths.build_file_list_by_extensions(str(tree), extensions = [".txt"])

    assert names(listed, tree) == ["docs/deep/notes.txt", "docs/readme.txt"]


def test_no_extensions_lists_everything(tree):
    assert len(paths.build_file_list_by_extensions(str(tree), extensions = [])) == 4


def test_a_symlinked_file_can_be_ignored(tree):
    link = tree / "link.zip"
    link.symlink_to(tree / "game.zip")
    listed = paths.build_file_list(str(tree), ignore_symlinks = True)

    assert not any(entry.endswith("link.zip") for entry in listed)


###########################################################
# Listing directories
###########################################################

def test_every_directory_is_listed(tree):
    listed = paths.build_directory_list(str(tree))
    relative = names(listed, tree)

    assert "docs" in relative
    assert "docs/deep" in relative
    assert "logs" in relative


def test_the_root_itself_is_listed(tree):
    listed = paths.build_directory_list(str(tree))

    assert os.path.abspath(str(tree)) in listed


def test_a_missing_root_lists_no_directories(tmp_path):
    assert paths.build_directory_list(str(tmp_path / "absent")) == []


def test_only_empty_directories_are_listed(tree):
    listed = paths.build_empty_directory_list(str(tree))

    assert names(listed, tree) == ["empty"]


def test_a_directory_holding_files_is_not_empty(tree):
    assert paths.is_directory_empty(str(tree / "docs")) is False


def test_a_directory_holding_nothing_is_empty(tree):
    assert paths.is_directory_empty(str(tree / "empty")) is True


def test_a_symlinked_directory_is_listed_separately(tree):
    link = tree / "docslink"
    link.symlink_to(tree / "docs")
    listed = paths.build_symlink_directory_list(str(tree))

    assert names(listed, tree) == ["docslink"]
    assert paths.does_directory_contain_symlink_dirs(str(tree)) is True


def test_a_tree_without_symlinks_reports_none(tree):
    assert paths.does_directory_contain_symlink_dirs(str(tree)) is False


###########################################################
# Exclude patterns
###########################################################

@pytest.mark.parametrize("pattern", ["*.log", "logs/**", "logs", "**/run.log"])
def test_a_log_file_is_matched_by_its_patterns(pattern):
    assert paths.matches_exclude_pattern(os.path.join("logs", "run.log"), [pattern]) is True


def test_an_unrelated_path_is_not_matched():
    assert paths.matches_exclude_pattern("game.zip", ["*.log", "logs/**"]) is False


def test_no_patterns_match_nothing():
    assert paths.matches_exclude_pattern("game.zip", []) is False


def test_a_directory_pattern_matches_its_whole_subtree():
    deep = os.path.join("logs", "nested", "deeper", "run.log")

    assert paths.matches_exclude_pattern(deep, ["logs/**"]) is True


def test_a_similarly_named_directory_is_not_matched():
    # "logs" must not take "logsarchive".
    assert paths.matches_exclude_pattern(
        os.path.join("logsarchive", "run.log"), ["logs/**"]) is False


###########################################################
# Leaf directories
###########################################################

def test_leaf_directories_are_the_ones_holding_files(tree):
    # Without a threshold this returns one list; with one it returns a pair.
    found = sorted(os.path.basename(entry["path"])
                   for entry in paths.build_leaf_directory_list(str(tree)))

    assert "deep" in found
    assert "logs" in found


def test_a_leaf_carries_its_file_count_and_size(tree):
    leaves = paths.build_leaf_directory_list(str(tree))
    logs = [entry for entry in leaves if entry["path"].endswith("logs")][0]

    assert logs["file_count"] == 1
    assert logs["total_size"] > 0


def test_a_threshold_splits_the_result_in_two(tree):
    # The sync separates these so one huge folder does not stall the batch.
    # The comparison is strict, so a leaf has to exceed the count.
    small, large = paths.build_leaf_directory_list(str(tree), large_file_count = 0)

    assert large
    assert all(entry["file_count"] > 0 for entry in large)


def test_a_leaf_at_the_threshold_is_not_large(tree):
    small, large = paths.build_leaf_directory_list(str(tree), large_file_count = 1)

    assert large == []
    assert small


def test_a_size_threshold_also_splits(tree):
    small, large = paths.build_leaf_directory_list(str(tree), large_total_size = 1)

    assert large


def test_a_generous_threshold_leaves_nothing_large(tree):
    small, large = paths.build_leaf_directory_list(
        str(tree), large_file_count = 10000, large_total_size = 10 ** 12)

    assert large == []
    assert small


def test_an_excluded_leaf_is_left_out(tree):
    leaves = paths.build_leaf_directory_list(str(tree), excludes = ["logs/**"])
    found = [os.path.basename(entry["path"]) for entry in leaves]

    assert "logs" not in found


###########################################################
# Path components
###########################################################

@pytest.mark.parametrize("path,expected", [
    ("/games/psx/game.cue", "game.cue"),
    ("game.cue", "game.cue"),
    ("/games/psx/", "psx"),
])
def test_the_directory_name_is_the_last_part(path, expected):
    assert paths.get_directory_name(path) == expected


def test_the_directory_parts_are_split():
    parts = paths.get_directory_parts("/games/psx/game.cue")

    assert parts[-2:] == ["psx", "game.cue"]


def test_the_directory_parent_drops_the_last_part():
    assert paths.get_directory_parent("/games/psx/game.cue").endswith("psx")


def test_the_directory_front_is_the_first_part():
    assert paths.get_directory_front("games/psx/game.cue") == "games"


def test_the_filename_front_is_the_first_part():
    assert paths.get_filename_front("games/psx/game.cue") == "games"


def test_the_front_of_a_bare_name_is_itself():
    assert paths.get_filename_front("game.cue") == "game.cue"


def test_the_filename_parts_are_split():
    assert paths.get_filename_parts("games/psx/game.cue")[-1] == "game.cue"


@pytest.mark.parametrize("path,expected", [
    ("/games/psx/game.cue", "/"),
    ("C:\\games\\game.cue", "C:\\"),
    ("relative/game.cue", ""),
])
def test_the_anchor_is_the_root(path, expected):
    assert paths.get_filename_anchor(path) == expected


@pytest.mark.parametrize("path,expected", [
    ("C:\\games\\game.cue", "c"),
    ("/games/psx/game.cue", "/"),
    ("relative/game.cue", ""),
])
def test_the_drive_is_taken_from_the_anchor(path, expected):
    assert paths.get_filename_drive(path) == expected


def test_the_drive_offset_is_the_rest_of_the_path():
    assert paths.get_filename_drive_offset("C:\\games\\game.cue") == "games\\game.cue"


def test_a_relative_path_is_all_offset():
    assert paths.get_filename_drive_offset("games/game.cue") == "games/game.cue"


def test_the_front_slice_removes_the_first_segment():
    assert paths.get_filename_front_slice("games/psx/game.cue") == \
        os.path.join("psx", "game.cue")


###########################################################
# Splitting
###########################################################

def test_a_path_is_split_on_its_separator():
    split = paths.split_file_path("/games/psx|/games/snes", "|")

    assert len(split) == 2


def test_the_first_part_keeps_its_root():
    split = paths.split_file_path("/games/psx|/games/snes", "|")

    assert split[0].startswith(os.sep)


def test_later_parts_are_made_relative():
    # Joined onto a root later, so an absolute second part would escape it.
    split = paths.split_file_path("/games/psx|/games/snes", "|")

    assert not os.path.isabs(split[1])


def test_a_path_without_the_separator_is_one_part():
    assert len(paths.split_file_path("/games/psx", "|")) == 1


###########################################################
# Top level paths
###########################################################

def test_a_list_is_reduced_to_its_first_segments():
    reduced = paths.convert_to_top_level_paths(
        ["games/psx/a.cue", "games/snes/b.sfc", "saves/c.sav"])

    assert reduced == ["games", "saves"]


def test_repeated_segments_are_collapsed():
    reduced = paths.convert_to_top_level_paths(
        ["games/psx/a.cue", "games/psx/b.cue", "games/snes/c.sfc"])

    assert reduced == ["games"]


def test_a_root_narrows_to_directories(tree):
    reduced = paths.convert_to_top_level_paths(
        ["docs/readme.txt", "game.zip"], path_root = str(tree), only_dirs = True)

    assert reduced == ["docs"]


def test_a_root_narrows_to_files(tree):
    reduced = paths.convert_to_top_level_paths(
        ["docs/readme.txt", "game.zip"], path_root = str(tree), only_files = True)

    assert reduced == ["game.zip"]


def test_an_empty_list_reduces_to_nothing():
    assert paths.convert_to_top_level_paths([]) == []


###########################################################
# File facts
###########################################################

def test_a_file_size_is_reported(tree):
    target = tree / "game.zip"

    assert paths.get_file_size(str(target)) == len(target.read_bytes())


def test_a_directory_size_sums_its_files(tree):
    assert paths.get_directory_size(str(tree / "docs")) > 0


def test_a_modification_time_is_reported(tree):
    assert paths.get_file_mod_time(str(tree / "game.zip")) > 0


def test_a_fresh_file_is_barely_any_hours_old(tree):
    assert paths.get_file_age_in_hours(str(tree / "game.zip")) < 1


def test_an_older_file_reports_its_age(tree):
    target = tree / "game.zip"
    stamp = time.time() - (5 * 3600)
    os.utime(str(target), (stamp, stamp))

    assert 4.9 < paths.get_file_age_in_hours(str(target)) < 5.1


def test_a_missing_file_is_infinitely_old(tmp_path):
    # Callers treat age as staleness, so an unreadable file must look stale
    # rather than fresh.
    assert paths.get_file_age_in_hours(str(tmp_path / "absent")) == float("inf")


def test_a_mime_type_is_reported(tree):
    assert paths.get_file_mime_type(str(tree / "docs" / "readme.txt"))


def test_directory_info_describes_the_directory(tree):
    info = paths.get_directory_info(str(tree / "docs"))

    assert isinstance(info, dict)
    assert info


def test_filename_info_describes_the_file(tree):
    info = paths.get_filename_info(str(tree / "game.zip"))

    assert isinstance(info, dict)
    assert info
