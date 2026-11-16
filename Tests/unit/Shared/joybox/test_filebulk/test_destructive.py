# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import fileops
from joybox import filebulk
from file_helpers import tree, write
from fileops_helpers import read


###########################################################
# filebulk transfers against a real filesystem
#
# Everything here either writes over a destination or deletes a source, so the
# skip flags and the dry run are the difference between a backup and a loss.
###########################################################


###########################################################
# Copying and moving contents
###########################################################

def test_a_nested_tree_copies_in_full(tmp_path):
    source = tmp_path / "src"
    write(source / "top.txt", "top")
    write(source / "deep" / "nested" / "leaf.txt", "leaf")
    dest = str(tmp_path / "dest")

    assert filebulk.copy_contents(str(source), dest) is True
    assert tree(dest) == [os.path.join("deep", "nested", "leaf.txt"), "top.txt"]
    assert read(os.path.join(dest, "deep", "nested", "leaf.txt")) == "leaf"


def test_copying_contents_leaves_the_source(tmp_path):
    source = tmp_path / "src"
    write(source / "top.txt", "content")
    dest = str(tmp_path / "dest")

    filebulk.copy_contents(str(source), dest)

    assert tree(source) == ["top.txt"]


def test_moving_contents_empties_the_source(tmp_path):
    source = tmp_path / "src"
    write(source / "top.txt", "content")
    write(source / "deep" / "leaf.txt", "content")
    dest = str(tmp_path / "dest")

    assert filebulk.move_contents(str(source), dest) is True
    assert tree(source) == []
    assert tree(dest) == [os.path.join("deep", "leaf.txt"), "top.txt"]


def test_copying_contents_merges_into_an_existing_destination(tmp_path):
    source = tmp_path / "src"
    write(source / "new.txt", "new")
    dest = tmp_path / "dest"
    write(dest / "kept.txt", "kept")

    filebulk.copy_contents(str(source), str(dest))

    assert tree(dest) == ["kept.txt", "new.txt"]


def test_symlinked_files_can_be_ignored(tmp_path):
    source = tmp_path / "src"
    write(source / "real.txt", "real")
    os.symlink(str(source / "real.txt"), str(source / "link.txt"))
    dest = str(tmp_path / "dest")

    filebulk.copy_contents(str(source), dest, ignore_symlinks = True)

    assert tree(dest) == ["real.txt"]


def test_symlinked_files_are_copied_by_default(tmp_path):
    source = tmp_path / "src"
    write(source / "real.txt", "real")
    os.symlink(str(source / "real.txt"), str(source / "link.txt"))
    dest = str(tmp_path / "dest")

    filebulk.copy_contents(str(source), dest)

    assert tree(dest) == ["link.txt", "real.txt"]


def test_a_symlinked_directory_can_be_followed(tmp_path):
    outside = tmp_path / "outside"
    write(outside / "leaf.txt", "leaf")
    source = tmp_path / "src"
    write(source / "top.txt", "content")
    os.symlink(str(outside), str(source / "linked"))
    dest = str(tmp_path / "dest")

    filebulk.copy_contents(str(source), dest, follow_symlink_dirs = True)

    assert os.path.join("linked", "leaf.txt") in tree(dest)


def test_a_symlinked_directory_is_not_followed_by_default(tmp_path):
    outside = tmp_path / "outside"
    write(outside / "leaf.txt", "leaf")
    source = tmp_path / "src"
    write(source / "top.txt", "content")
    os.symlink(str(outside), str(source / "linked"))
    dest = str(tmp_path / "dest")

    filebulk.copy_contents(str(source), dest)

    assert tree(dest) == ["top.txt"]


def test_pretending_does_not_copy_contents(tmp_path):
    source = tmp_path / "src"
    write(source / "top.txt", "content")
    dest = str(tmp_path / "dest")

    assert filebulk.copy_contents(str(source), dest, pretend_run = True) is True
    assert not os.path.exists(dest)


def test_pretending_does_not_move_contents(tmp_path):
    source = tmp_path / "src"
    write(source / "top.txt", "content")

    filebulk.move_contents(str(source), str(tmp_path / "dest"), pretend_run = True)

    assert tree(source) == ["top.txt"]


def test_copying_from_a_missing_source_can_quit_the_program(tmp_path):
    with pytest.raises(SystemExit):
        filebulk.copy_contents(
            str(tmp_path / "absent"),
            str(tmp_path / "dest"),
            exit_on_failure = True)


def test_moving_from_a_missing_source_can_quit_the_program(tmp_path):
    with pytest.raises(SystemExit):
        filebulk.move_contents(
            str(tmp_path / "absent"),
            str(tmp_path / "dest"),
            exit_on_failure = True)


def test_identical_files_are_skipped_across_a_whole_tree(tmp_path):
    source = tmp_path / "src"
    write(source / "same.txt", "same")
    write(source / "differs.txt", "new")
    dest = tmp_path / "dest"
    write(dest / "same.txt", "same")
    write(dest / "differs.txt", "old")

    filebulk.copy_contents(str(source), str(dest), skip_identical = True)

    assert read(dest / "differs.txt") == "new"


###########################################################
# Globbed copies and moves
###########################################################

def test_only_matching_files_are_copied(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt", "content")
    write(source / "other.dat", "content")
    dest = str(tmp_path / "dest")

    assert filebulk.copy_globbed_files(str(source / "*.txt"), dest) is True
    assert tree(dest) == ["keep.txt"]


def test_a_glob_copy_leaves_the_matches_in_place(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt", "content")

    filebulk.copy_globbed_files(str(source / "*.txt"), str(tmp_path / "dest"))

    assert tree(source) == ["keep.txt"]


def test_a_glob_move_removes_the_matches(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt", "payload")
    write(source / "other.dat", "kept")
    dest = str(tmp_path / "dest")

    assert filebulk.move_globbed_files(str(source / "*.txt"), dest) is True
    assert tree(source) == ["other.dat"]
    assert read(os.path.join(dest, "keep.txt")) == "payload"


def test_a_glob_that_matches_nothing_is_success(tmp_path):
    source = tmp_path / "src"
    write(source / "other.dat", "content")

    assert filebulk.copy_globbed_files(str(source / "*.txt"), str(tmp_path / "dest")) is True


def test_a_glob_move_that_matches_a_directory_copies_its_name(tmp_path):
    # A directory match cannot be opened as a file, so it is reported rather
    # than silently dropped.
    source = tmp_path / "src"
    os.makedirs(str(source / "subdir"))

    assert filebulk.move_globbed_files(str(source / "*"), str(tmp_path / "dest")) is False


def test_pretending_does_not_move_globbed_files(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt", "content")

    filebulk.move_globbed_files(str(source / "*.txt"), str(tmp_path / "dest"), pretend_run = True)

    assert tree(source) == ["keep.txt"]


###########################################################
# Smart copy, move and transfer
###########################################################

def test_a_smart_copy_of_a_directory_copies_its_contents(tmp_path):
    source = tmp_path / "src"
    write(source / "deep" / "leaf.txt", "leaf")
    dest = str(tmp_path / "dest")

    assert filebulk.smart_copy(str(source), dest) is True
    assert tree(dest) == [os.path.join("deep", "leaf.txt")]


def test_a_smart_copy_of_a_glob_copies_the_matches(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt", "content")
    write(source / "other.dat", "content")
    dest = str(tmp_path / "dest")

    assert filebulk.smart_copy(str(source / "*.txt"), dest) is True
    assert tree(dest) == ["keep.txt"]


def test_a_smart_move_of_a_directory_empties_it(tmp_path):
    source = tmp_path / "src"
    write(source / "deep" / "leaf.txt", "leaf")
    dest = str(tmp_path / "dest")

    assert filebulk.smart_move(str(source), dest) is True
    assert tree(source) == []
    assert tree(dest) == [os.path.join("deep", "leaf.txt")]


def test_a_smart_move_of_a_glob_removes_the_matches(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt", "content")
    dest = str(tmp_path / "dest")

    assert filebulk.smart_move(str(source / "*.txt"), dest) is True
    assert tree(source) == []
    assert tree(dest) == ["keep.txt"]


def test_a_smart_transfer_copies_when_told_to_keep_the_source(tmp_path):
    source = write(tmp_path / "src.txt", "payload")
    dest = str(tmp_path / "out" / "dest.txt")

    assert filebulk.smart_transfer(source, dest) is True
    assert os.path.isfile(source)
    assert read(dest) == "payload"


def test_a_smart_transfer_moves_when_told_to_delete_the_source(tmp_path):
    source = write(tmp_path / "src.txt", "payload")
    dest = str(tmp_path / "out" / "dest.txt")

    assert filebulk.smart_transfer(source, dest, delete_afterwards = True) is True
    assert not os.path.exists(source)
    assert read(dest) == "payload"


def test_a_smart_transfer_of_a_directory_keeps_the_tree(tmp_path):
    source = tmp_path / "src"
    write(source / "deep" / "leaf.txt", "leaf")
    dest = str(tmp_path / "dest")

    assert filebulk.smart_transfer(str(source), dest, delete_afterwards = True) is True
    assert tree(dest) == [os.path.join("deep", "leaf.txt")]


###########################################################
# Syncing
###########################################################

def test_a_sync_replaces_what_the_destination_held(tmp_path):
    source = tmp_path / "src"
    write(source / "new.txt", "new")
    dest = tmp_path / "dest"
    write(dest / "stale.txt", "stale")

    assert filebulk.sync_contents(str(source), str(dest)) is True
    assert tree(dest) == ["new.txt"]


def test_a_sync_creates_a_missing_destination(tmp_path):
    source = tmp_path / "src"
    write(source / "new.txt", "new")
    dest = str(tmp_path / "dest")

    assert filebulk.sync_contents(str(source), dest) is True
    assert tree(dest) == ["new.txt"]


def test_a_sync_leaves_the_source_alone(tmp_path):
    source = tmp_path / "src"
    write(source / "new.txt", "new")

    filebulk.sync_contents(str(source), str(tmp_path / "dest"))

    assert tree(source) == ["new.txt"]


def test_syncing_from_a_missing_source_can_quit_the_program(tmp_path):
    # Without the guard the destination is emptied and then filled from
    # nothing, which is a silent wipe.
    with pytest.raises(SystemExit):
        filebulk.sync_contents(
            str(tmp_path / "absent"),
            str(tmp_path / "dest"),
            exit_on_failure = True)


def test_pretending_does_not_sync(tmp_path):
    source = tmp_path / "src"
    write(source / "new.txt", "new")
    dest = tmp_path / "dest"
    write(dest / "stale.txt", "stale")

    filebulk.sync_contents(str(source), str(dest), pretend_run = True)

    assert tree(dest) == ["stale.txt"]


def test_syncing_data_from_a_directory_mirrors_it(tmp_path):
    source = tmp_path / "src"
    write(source / "new.txt", "new")
    dest = tmp_path / "dest"
    write(dest / "stale.txt", "stale")

    assert filebulk.sync_data(str(source), str(dest)) is True
    assert tree(dest) == ["new.txt"]


def test_syncing_data_from_a_file_copies_it(tmp_path):
    source = write(tmp_path / "src.txt", "payload")
    dest = str(tmp_path / "out" / "dest.txt")

    assert filebulk.sync_data(source, dest) is True
    assert read(dest) == "payload"


def test_syncing_data_from_a_glob_copies_the_matches(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt", "content")
    write(source / "other.dat", "content")
    dest = tmp_path / "dest"

    assert filebulk.sync_data(str(source / "*.txt"), str(dest / "*.txt")) is True
    assert tree(dest) == ["keep.txt"]


def test_syncing_data_from_a_missing_source_reports_failure(tmp_path):
    assert filebulk.sync_data(str(tmp_path / "absent"), str(tmp_path / "dest")) is False


###########################################################
# Smart transfers
###########################################################

def test_a_smart_copy_creates_missing_parents(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("content")
    target = tmp_path / "a" / "b" / "target.txt"

    assert filebulk.smart_copy(str(source), str(target)) is True
    assert target.read_text() == "content"


def test_a_smart_copy_leaves_the_source(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("content")
    filebulk.smart_copy(str(source), str(tmp_path / "target.txt"))

    assert source.exists()


def test_a_smart_move_removes_the_source(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("content")
    filebulk.smart_move(str(source), str(tmp_path / "target.txt"))

    assert not source.exists()
    assert (tmp_path / "target.txt").read_text() == "content"


def test_a_smart_copy_can_skip_an_existing_target(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("new")
    target = tmp_path / "target.txt"
    target.write_text("old")
    filebulk.smart_copy(str(source), str(target), skip_existing = True)

    assert target.read_text() == "old"


def test_a_smart_copy_skips_an_identical_target(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("same")
    target = tmp_path / "target.txt"
    target.write_text("same")

    assert filebulk.smart_copy(str(source), str(target), skip_identical = True) is True
    assert target.read_text() == "same"


def test_a_glob_copies_every_match(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in ["a.cue", "b.cue", "c.bin"]:
        (source / name).write_text(name)
    target = tmp_path / "target"

    filebulk.smart_copy(str(source / "*.cue"), str(target))
    assert sorted(os.listdir(str(target))) == ["a.cue", "b.cue"]


def test_a_directory_copies_with_its_tree(tmp_path):
    source = tmp_path / "source"
    (source / "nested").mkdir(parents = True)
    (source / "nested" / "file.txt").write_text("content")
    target = tmp_path / "target"

    filebulk.smart_copy(str(source), str(target))
    assert (target / "nested" / "file.txt").read_text() == "content"


###########################################################
# Contents
###########################################################

def test_contents_are_copied_without_the_directory_itself(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content")
    target = tmp_path / "target"
    target.mkdir()

    assert filebulk.copy_contents(str(source), str(target)) is True
    assert (target / "file.txt").exists()
    assert not (target / "source").exists()


def test_contents_are_moved_without_the_directory_itself(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content")
    target = tmp_path / "target"
    target.mkdir()
    filebulk.move_contents(str(source), str(target))

    assert (target / "file.txt").exists()
    assert not (source / "file.txt").exists()


def test_moving_contents_keeps_the_source_directory(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content")
    target = tmp_path / "target"
    target.mkdir()
    filebulk.move_contents(str(source), str(target))

    assert source.is_dir()


def test_the_directory_itself_is_chmodded(tmp_path):
    # Its contents are unreachable otherwise when the directory is the read
    # only one, which is exactly what an extracted iso leaves behind.
    root = tmp_path / "tree"
    root.mkdir()
    (root / "file.txt").write_text("content")
    os.chmod(str(root), 0o555)
    fileops.chmod_file_or_directory(str(root), "777")

    assert oct(os.stat(str(root)).st_mode)[-3:] == "777"


def test_a_read_only_directory_can_then_be_emptied(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "file.txt").write_text("content")
    os.chmod(str(root), 0o555)
    fileops.chmod_file_or_directory(str(root), "777")

    assert fileops.remove_directory_contents(str(root)) is True
    assert os.listdir(str(root)) == []


def test_the_directory_takes_the_directory_permissions(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "file.txt").write_text("content")
    fileops.chmod_file_or_directory(str(root), "644", dperms = "755")

    assert oct(os.stat(str(root)).st_mode)[-3:] == "755"
