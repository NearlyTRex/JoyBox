# Imports
import os
import stat

# Third-party imports
import pytest

# Local imports
from joybox import fileops
from joybox import filebulk
from file_helpers import tree, write
from fileops_helpers import read



###########################################################
# fileops transfers against a real filesystem
#
# Everything here either writes over a destination or deletes a source, so the
# skip flags and the dry run are the difference between a backup and a loss.
###########################################################


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

    payload = "x" * (config.TRANSFER_CHUNK_SIZE * 2 + 17)
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


def test_an_unwritable_error_log_does_not_raise(tmp_path, monkeypatch):
    # Losing the log is not worth aborting a long bulk copy over.
    warnings = []
    monkeypatch.setattr(fileops.logger, "log_warning", warnings.append)
    unwritable = str(tmp_path / "missing-dir" / "errors.log")

    fileops.report_fileio_error("/first.txt", None, unwritable)

    assert warnings[-1].startswith("Unable to write error log '%s'" % unwritable)
    assert not os.path.exists(unwritable)


###########################################################
# Removing by pattern
###########################################################

def test_every_glob_match_is_removed(tmp_path):
    write(tmp_path / "one.txt", "content")
    write(tmp_path / "two.txt", "content")
    write(tmp_path / "kept.dat", "content")

    assert fileops.remove_file_or_directory(str(tmp_path / "*.txt")) is True
    assert tree(tmp_path) == ["kept.dat"]


def test_a_glob_removal_takes_directories_too(tmp_path):
    write(tmp_path / "dir.txt" / "leaf.txt", "content")
    write(tmp_path / "kept.dat", "content")

    fileops.remove_file_or_directory(str(tmp_path / "*.txt"))

    assert tree(tmp_path) == ["kept.dat"]


def test_removing_a_pattern_that_matches_nothing_is_success(tmp_path):
    assert fileops.remove_file_or_directory(str(tmp_path / "*.txt")) is True


def test_pretending_does_not_remove_matches(tmp_path):
    write(tmp_path / "one.txt", "content")

    assert fileops.remove_file_or_directory(str(tmp_path / "*.txt"), pretend_run = True) is True
    assert tree(tmp_path) == ["one.txt"]


def test_an_object_is_removed_by_its_type(tmp_path):
    target = write(tmp_path / "file.txt", "content")

    assert fileops.remove_object(target) is True
    assert not os.path.exists(target)


def test_a_symlink_is_removed_without_its_target(tmp_path):
    target = write(tmp_path / "real.txt", "content")
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
    write(target / "deep" / "leaf.txt", "content")

    assert fileops.remove_object(str(target)) is True
    assert not os.path.exists(str(target))


def test_removing_a_missing_object_reports_failure(tmp_path):
    assert fileops.remove_object(str(tmp_path / "absent.txt")) is False


def test_syncing_data_from_a_missing_source_can_quit_the_program(tmp_path):
    with pytest.raises(SystemExit):
        filebulk.sync_data(
            str(tmp_path / "absent"),
            str(tmp_path / "dest"),
            exit_on_failure = True)
