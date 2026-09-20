# Imports
import os
import stat

# Third-party imports
import pytest

# Local imports
from joybox import fileops


###########################################################
# fileops transfers against a real filesystem
#
# Everything here either writes over a destination or deletes a source, so the
# skip flags and the dry run are the difference between a backup and a loss.
###########################################################

def write(path, contents = "content"):
    path = str(path)
    os.makedirs(os.path.dirname(path), exist_ok = True)
    with open(path, "w") as target:
        target.write(contents)
    return path


def read(path):
    with open(str(path), "r") as target:
        return target.read()


def tree(root):
    # Every file under root, relative and sorted, so a layout can be compared
    # as a whole rather than one exists() call at a time.
    found = []
    for directory, _, filenames in os.walk(str(root)):
        for filename in filenames:
            found.append(os.path.relpath(os.path.join(directory, filename), str(root)))
    return sorted(found)


###########################################################
# Transferring a single file
###########################################################

def test_a_file_is_transferred_with_its_contents(tmp_path):
    source = write(tmp_path / "src.txt", "payload")
    target = str(tmp_path / "dest.txt")

    assert fileops.transfer_file(source, target) is True
    assert read(target) == "payload"
    assert os.path.isfile(source)


def test_a_transfer_spans_several_chunks(tmp_path):
    # The copy loop reads a fixed size at a time; a file smaller than one chunk
    # never exercises the second iteration.
    from joybox.config import general as config

    payload = "x" * (config.transfer_chunk_size * 2 + 17)
    source = write(tmp_path / "big.bin", payload)
    target = str(tmp_path / "big-copy.bin")

    assert fileops.transfer_file(source, target) is True
    assert read(target) == payload


def test_a_transfer_keeps_the_executable_bit(tmp_path):
    source = write(tmp_path / "run.sh", "#!/bin/sh\n")
    os.chmod(source, 0o755)
    target = str(tmp_path / "run-copy.sh")

    fileops.transfer_file(source, target)

    assert bool(os.stat(target).st_mode & stat.S_IXUSR)


def test_a_transfer_can_delete_the_source(tmp_path):
    source = write(tmp_path / "src.txt", "payload")
    target = str(tmp_path / "dest.txt")

    assert fileops.transfer_file(source, target, delete_afterwards = True) is True
    assert read(target) == "payload"
    assert not os.path.exists(source)


def test_transferring_a_file_onto_itself_leaves_it_intact(tmp_path):
    # Opening the same path for reading and writing truncates it first, so a
    # self transfer that is not short circuited destroys the file.
    source = write(tmp_path / "src.txt", "payload")

    assert fileops.transfer_file(source, source) is True
    assert read(source) == "payload"


def test_transferring_a_file_onto_itself_does_not_delete_it(tmp_path):
    source = write(tmp_path / "src.txt", "payload")

    assert fileops.transfer_file(source, source, delete_afterwards = True) is True
    assert read(source) == "payload"


def test_a_relative_path_to_the_same_file_is_recognised(tmp_path, monkeypatch):
    source = write(tmp_path / "src.txt", "payload")
    monkeypatch.chdir(str(tmp_path))

    assert fileops.transfer_file("src.txt", source) is True
    assert read(source) == "payload"


def test_an_existing_destination_can_be_skipped(tmp_path):
    source = write(tmp_path / "src.txt", "new")
    target = write(tmp_path / "dest.txt", "old")

    assert fileops.transfer_file(source, target, skip_existing = True) is True
    assert read(target) == "old"


def test_an_existing_destination_is_overwritten_by_default(tmp_path):
    source = write(tmp_path / "src.txt", "new")
    target = write(tmp_path / "dest.txt", "old")

    assert fileops.transfer_file(source, target) is True
    assert read(target) == "new"


def test_skipping_an_existing_destination_keeps_the_source(tmp_path):
    # The skip happens before the delete, so a skipped move must not be a
    # silent deletion of the source.
    source = write(tmp_path / "src.txt", "new")
    target = write(tmp_path / "dest.txt", "old")

    fileops.transfer_file(source, target, skip_existing = True, delete_afterwards = True)

    assert read(source) == "new"


def test_an_identical_destination_is_skipped(tmp_path):
    source = write(tmp_path / "src.txt", "same")
    target = write(tmp_path / "dest.txt", "same")
    before = os.stat(target).st_mtime_ns

    assert fileops.transfer_file(source, target, skip_identical = True) is True
    assert os.stat(target).st_mtime_ns == before


def test_a_differing_destination_is_not_skipped_as_identical(tmp_path):
    source = write(tmp_path / "src.txt", "new")
    target = write(tmp_path / "dest.txt", "old")

    assert fileops.transfer_file(source, target, skip_identical = True) is True
    assert read(target) == "new"


def test_pretending_does_not_transfer(tmp_path):
    source = write(tmp_path / "src.txt", "payload")
    target = str(tmp_path / "dest.txt")

    assert fileops.transfer_file(source, target, pretend_run = True) is True
    assert not os.path.exists(target)


def test_pretending_does_not_delete_the_source(tmp_path):
    source = write(tmp_path / "src.txt", "payload")
    target = str(tmp_path / "dest.txt")

    fileops.transfer_file(source, target, delete_afterwards = True, pretend_run = True)

    assert os.path.isfile(source)


def test_transferring_a_missing_file_reports_failure(tmp_path):
    assert fileops.transfer_file(str(tmp_path / "absent.txt"), str(tmp_path / "dest.txt")) is False


def test_transferring_a_directory_reports_failure(tmp_path):
    source = str(tmp_path / "dir")
    os.makedirs(source)

    assert fileops.transfer_file(source, str(tmp_path / "dest.txt")) is False


def test_a_failed_transfer_can_quit_the_program(tmp_path):
    with pytest.raises(SystemExit):
        fileops.transfer_file(
            str(tmp_path / "absent.txt"),
            str(tmp_path / "dest.txt"),
            exit_on_failure = True)


def test_skipping_on_error_takes_precedence_over_quitting(tmp_path):
    # A bulk run that was told to skip bad files must not exit on the first one.
    assert fileops.transfer_file(
        str(tmp_path / "absent.txt"),
        str(tmp_path / "dest.txt"),
        skip_on_error = True,
        exit_on_failure = True) is False


def test_a_skipped_transfer_is_written_to_the_error_log(tmp_path):
    log = str(tmp_path / "errors.log")

    fileops.transfer_file(
        str(tmp_path / "absent.txt"),
        str(tmp_path / "dest.txt"),
        skip_on_error = True,
        error_log_path = log)

    assert str(tmp_path / "absent.txt") in read(log)


###########################################################
# Reporting a per-file error
###########################################################

def test_a_partial_destination_is_removed(tmp_path):
    # A half written destination that survives the error looks like a good
    # copy to the next run.
    partial = write(tmp_path / "dest.txt", "half")

    fileops.report_fileio_error(str(tmp_path / "src.txt"), partial)

    assert not os.path.exists(partial)


def test_pretending_leaves_the_destination_alone(tmp_path):
    partial = write(tmp_path / "dest.txt", "half")

    fileops.report_fileio_error(str(tmp_path / "src.txt"), partial, pretend_run = True)

    assert os.path.isfile(partial)


def test_each_failure_appends_to_the_error_log(tmp_path):
    log = str(tmp_path / "errors.log")

    fileops.report_fileio_error("/first.txt", None, log)
    fileops.report_fileio_error("/second.txt", None, log)

    assert read(log).split() == ["/first.txt", "/second.txt"]


def test_an_unwritable_error_log_does_not_raise(tmp_path):
    # Losing the log is not worth aborting a long bulk copy over.
    unwritable = str(tmp_path / "missing-dir" / "errors.log")

    fileops.report_fileio_error("/first.txt", None, unwritable)


###########################################################
# Copying and moving contents
###########################################################

def test_a_nested_tree_copies_in_full(tmp_path):
    source = tmp_path / "src"
    write(source / "top.txt", "top")
    write(source / "deep" / "nested" / "leaf.txt", "leaf")
    dest = str(tmp_path / "dest")

    assert fileops.copy_contents(str(source), dest) is True
    assert tree(dest) == [os.path.join("deep", "nested", "leaf.txt"), "top.txt"]
    assert read(os.path.join(dest, "deep", "nested", "leaf.txt")) == "leaf"


def test_copying_contents_leaves_the_source(tmp_path):
    source = tmp_path / "src"
    write(source / "top.txt")
    dest = str(tmp_path / "dest")

    fileops.copy_contents(str(source), dest)

    assert tree(source) == ["top.txt"]


def test_moving_contents_empties_the_source(tmp_path):
    source = tmp_path / "src"
    write(source / "top.txt")
    write(source / "deep" / "leaf.txt")
    dest = str(tmp_path / "dest")

    assert fileops.move_contents(str(source), dest) is True
    assert tree(source) == []
    assert tree(dest) == [os.path.join("deep", "leaf.txt"), "top.txt"]


def test_copying_contents_merges_into_an_existing_destination(tmp_path):
    source = tmp_path / "src"
    write(source / "new.txt", "new")
    dest = tmp_path / "dest"
    write(dest / "kept.txt", "kept")

    fileops.copy_contents(str(source), str(dest))

    assert tree(dest) == ["kept.txt", "new.txt"]


def test_symlinked_files_can_be_ignored(tmp_path):
    source = tmp_path / "src"
    write(source / "real.txt", "real")
    os.symlink(str(source / "real.txt"), str(source / "link.txt"))
    dest = str(tmp_path / "dest")

    fileops.copy_contents(str(source), dest, ignore_symlinks = True)

    assert tree(dest) == ["real.txt"]


def test_symlinked_files_are_copied_by_default(tmp_path):
    source = tmp_path / "src"
    write(source / "real.txt", "real")
    os.symlink(str(source / "real.txt"), str(source / "link.txt"))
    dest = str(tmp_path / "dest")

    fileops.copy_contents(str(source), dest)

    assert tree(dest) == ["link.txt", "real.txt"]


def test_a_symlinked_directory_can_be_followed(tmp_path):
    outside = tmp_path / "outside"
    write(outside / "leaf.txt", "leaf")
    source = tmp_path / "src"
    write(source / "top.txt")
    os.symlink(str(outside), str(source / "linked"))
    dest = str(tmp_path / "dest")

    fileops.copy_contents(str(source), dest, follow_symlink_dirs = True)

    assert os.path.join("linked", "leaf.txt") in tree(dest)


def test_a_symlinked_directory_is_not_followed_by_default(tmp_path):
    outside = tmp_path / "outside"
    write(outside / "leaf.txt", "leaf")
    source = tmp_path / "src"
    write(source / "top.txt")
    os.symlink(str(outside), str(source / "linked"))
    dest = str(tmp_path / "dest")

    fileops.copy_contents(str(source), dest)

    assert tree(dest) == ["top.txt"]


def test_pretending_does_not_copy_contents(tmp_path):
    source = tmp_path / "src"
    write(source / "top.txt")
    dest = str(tmp_path / "dest")

    assert fileops.copy_contents(str(source), dest, pretend_run = True) is True
    assert not os.path.exists(dest)


def test_pretending_does_not_move_contents(tmp_path):
    source = tmp_path / "src"
    write(source / "top.txt")

    fileops.move_contents(str(source), str(tmp_path / "dest"), pretend_run = True)

    assert tree(source) == ["top.txt"]


def test_copying_from_a_missing_source_can_quit_the_program(tmp_path):
    with pytest.raises(SystemExit):
        fileops.copy_contents(
            str(tmp_path / "absent"),
            str(tmp_path / "dest"),
            exit_on_failure = True)


def test_moving_from_a_missing_source_can_quit_the_program(tmp_path):
    with pytest.raises(SystemExit):
        fileops.move_contents(
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

    fileops.copy_contents(str(source), str(dest), skip_identical = True)

    assert read(dest / "differs.txt") == "new"


###########################################################
# Globbed copies and moves
###########################################################

def test_only_matching_files_are_copied(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt")
    write(source / "other.dat")
    dest = str(tmp_path / "dest")

    assert fileops.copy_globbed_files(str(source / "*.txt"), dest) is True
    assert tree(dest) == ["keep.txt"]


def test_a_glob_copy_leaves_the_matches_in_place(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt")

    fileops.copy_globbed_files(str(source / "*.txt"), str(tmp_path / "dest"))

    assert tree(source) == ["keep.txt"]


def test_a_glob_move_removes_the_matches(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt", "payload")
    write(source / "other.dat", "kept")
    dest = str(tmp_path / "dest")

    assert fileops.move_globbed_files(str(source / "*.txt"), dest) is True
    assert tree(source) == ["other.dat"]
    assert read(os.path.join(dest, "keep.txt")) == "payload"


def test_a_glob_that_matches_nothing_is_success(tmp_path):
    source = tmp_path / "src"
    write(source / "other.dat")

    assert fileops.copy_globbed_files(str(source / "*.txt"), str(tmp_path / "dest")) is True


def test_a_glob_move_that_matches_a_directory_copies_its_name(tmp_path):
    # A directory match cannot be opened as a file, so it is reported rather
    # than silently dropped.
    source = tmp_path / "src"
    os.makedirs(str(source / "subdir"))

    assert fileops.move_globbed_files(str(source / "*"), str(tmp_path / "dest")) is False


def test_pretending_does_not_move_globbed_files(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt")

    fileops.move_globbed_files(str(source / "*.txt"), str(tmp_path / "dest"), pretend_run = True)

    assert tree(source) == ["keep.txt"]


###########################################################
# Smart copy, move and transfer
###########################################################

def test_a_smart_copy_of_a_directory_copies_its_contents(tmp_path):
    source = tmp_path / "src"
    write(source / "deep" / "leaf.txt", "leaf")
    dest = str(tmp_path / "dest")

    assert fileops.smart_copy(str(source), dest) is True
    assert tree(dest) == [os.path.join("deep", "leaf.txt")]


def test_a_smart_copy_of_a_glob_copies_the_matches(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt")
    write(source / "other.dat")
    dest = str(tmp_path / "dest")

    assert fileops.smart_copy(str(source / "*.txt"), dest) is True
    assert tree(dest) == ["keep.txt"]


def test_a_smart_move_of_a_directory_empties_it(tmp_path):
    source = tmp_path / "src"
    write(source / "deep" / "leaf.txt", "leaf")
    dest = str(tmp_path / "dest")

    assert fileops.smart_move(str(source), dest) is True
    assert tree(source) == []
    assert tree(dest) == [os.path.join("deep", "leaf.txt")]


def test_a_smart_move_of_a_glob_removes_the_matches(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt")
    dest = str(tmp_path / "dest")

    assert fileops.smart_move(str(source / "*.txt"), dest) is True
    assert tree(source) == []
    assert tree(dest) == ["keep.txt"]


def test_a_smart_transfer_copies_when_told_to_keep_the_source(tmp_path):
    source = write(tmp_path / "src.txt", "payload")
    dest = str(tmp_path / "out" / "dest.txt")

    assert fileops.smart_transfer(source, dest) is True
    assert os.path.isfile(source)
    assert read(dest) == "payload"


def test_a_smart_transfer_moves_when_told_to_delete_the_source(tmp_path):
    source = write(tmp_path / "src.txt", "payload")
    dest = str(tmp_path / "out" / "dest.txt")

    assert fileops.smart_transfer(source, dest, delete_afterwards = True) is True
    assert not os.path.exists(source)
    assert read(dest) == "payload"


def test_a_smart_transfer_of_a_directory_keeps_the_tree(tmp_path):
    source = tmp_path / "src"
    write(source / "deep" / "leaf.txt", "leaf")
    dest = str(tmp_path / "dest")

    assert fileops.smart_transfer(str(source), dest, delete_afterwards = True) is True
    assert tree(dest) == [os.path.join("deep", "leaf.txt")]


###########################################################
# Syncing
###########################################################

def test_a_sync_replaces_what_the_destination_held(tmp_path):
    source = tmp_path / "src"
    write(source / "new.txt", "new")
    dest = tmp_path / "dest"
    write(dest / "stale.txt", "stale")

    assert fileops.sync_contents(str(source), str(dest)) is True
    assert tree(dest) == ["new.txt"]


def test_a_sync_creates_a_missing_destination(tmp_path):
    source = tmp_path / "src"
    write(source / "new.txt", "new")
    dest = str(tmp_path / "dest")

    assert fileops.sync_contents(str(source), dest) is True
    assert tree(dest) == ["new.txt"]


def test_a_sync_leaves_the_source_alone(tmp_path):
    source = tmp_path / "src"
    write(source / "new.txt", "new")

    fileops.sync_contents(str(source), str(tmp_path / "dest"))

    assert tree(source) == ["new.txt"]


def test_syncing_from_a_missing_source_can_quit_the_program(tmp_path):
    # Without the guard the destination is emptied and then filled from
    # nothing, which is a silent wipe.
    with pytest.raises(SystemExit):
        fileops.sync_contents(
            str(tmp_path / "absent"),
            str(tmp_path / "dest"),
            exit_on_failure = True)


def test_pretending_does_not_sync(tmp_path):
    source = tmp_path / "src"
    write(source / "new.txt", "new")
    dest = tmp_path / "dest"
    write(dest / "stale.txt", "stale")

    fileops.sync_contents(str(source), str(dest), pretend_run = True)

    assert tree(dest) == ["stale.txt"]


def test_syncing_data_from_a_directory_mirrors_it(tmp_path):
    source = tmp_path / "src"
    write(source / "new.txt", "new")
    dest = tmp_path / "dest"
    write(dest / "stale.txt", "stale")

    assert fileops.sync_data(str(source), str(dest)) is True
    assert tree(dest) == ["new.txt"]


def test_syncing_data_from_a_file_copies_it(tmp_path):
    source = write(tmp_path / "src.txt", "payload")
    dest = str(tmp_path / "out" / "dest.txt")

    assert fileops.sync_data(source, dest) is True
    assert read(dest) == "payload"


def test_syncing_data_from_a_glob_copies_the_matches(tmp_path):
    source = tmp_path / "src"
    write(source / "keep.txt")
    write(source / "other.dat")
    dest = tmp_path / "dest"

    assert fileops.sync_data(str(source / "*.txt"), str(dest / "*.txt")) is True
    assert tree(dest) == ["keep.txt"]


def test_syncing_data_from_a_missing_source_reports_failure(tmp_path):
    assert fileops.sync_data(str(tmp_path / "absent"), str(tmp_path / "dest")) is False


###########################################################
# Removing by pattern
###########################################################

def test_every_glob_match_is_removed(tmp_path):
    write(tmp_path / "one.txt")
    write(tmp_path / "two.txt")
    write(tmp_path / "kept.dat")

    assert fileops.remove_file_or_directory(str(tmp_path / "*.txt")) is True
    assert tree(tmp_path) == ["kept.dat"]


def test_a_glob_removal_takes_directories_too(tmp_path):
    write(tmp_path / "dir.txt" / "leaf.txt")
    write(tmp_path / "kept.dat")

    fileops.remove_file_or_directory(str(tmp_path / "*.txt"))

    assert tree(tmp_path) == ["kept.dat"]


def test_removing_a_pattern_that_matches_nothing_is_success(tmp_path):
    assert fileops.remove_file_or_directory(str(tmp_path / "*.txt")) is True


def test_pretending_does_not_remove_matches(tmp_path):
    write(tmp_path / "one.txt")

    assert fileops.remove_file_or_directory(str(tmp_path / "*.txt"), pretend_run = True) is True
    assert tree(tmp_path) == ["one.txt"]


def test_an_object_is_removed_by_its_type(tmp_path):
    target = write(tmp_path / "file.txt")

    assert fileops.remove_object(target) is True
    assert not os.path.exists(target)


def test_a_symlink_is_removed_without_its_target(tmp_path):
    target = write(tmp_path / "real.txt")
    link = str(tmp_path / "link.txt")
    os.symlink(target, link)

    assert fileops.remove_object(link) is True
    assert not os.path.exists(link)
    assert os.path.isfile(target)


def test_a_broken_symlink_is_removed(tmp_path):
    # isfile() is False for a dangling link, so it falls to the symlink branch
    # or it is left behind forever.
    link = str(tmp_path / "link.txt")
    os.symlink(str(tmp_path / "absent.txt"), link)

    assert fileops.remove_object(link) is True
    assert not os.path.islink(link)


def test_a_directory_object_is_removed_with_its_contents(tmp_path):
    target = tmp_path / "dir"
    write(target / "deep" / "leaf.txt")

    assert fileops.remove_object(str(target)) is True
    assert not os.path.exists(str(target))


def test_removing_a_missing_object_reports_failure(tmp_path):
    assert fileops.remove_object(str(tmp_path / "absent.txt")) is False


def test_syncing_data_from_a_missing_source_can_quit_the_program(tmp_path):
    with pytest.raises(SystemExit):
        fileops.sync_data(
            str(tmp_path / "absent"),
            str(tmp_path / "dest"),
            exit_on_failure = True)
