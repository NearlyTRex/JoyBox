# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import runoptions
from joybox.connection import connection_local


###########################################################
# ConnectionLocal against a real filesystem
#
# Unit tests use a recording double for this interface, so something has to
# confirm the real implementation honours the same contract.
###########################################################

@pytest.fixture
def local_connection():
    return connection_local.ConnectionLocal(
        runoptions.RunFlags(verbose = False),
        runoptions.RunOptions())


###########################################################
# Files
###########################################################

def test_write_then_read_round_trips(local_connection, tmp_path):
    target = str(tmp_path / "note.txt")

    assert local_connection.write_file(target, "hello\nworld\n")
    assert local_connection.read_file(target) == "hello\nworld\n"


def test_written_file_exists_on_disk(local_connection, tmp_path):
    target = str(tmp_path / "note.txt")
    local_connection.write_file(target, "content")

    assert os.path.isfile(target)
    assert local_connection.does_file_or_directory_exist(target)


def test_missing_paths_are_reported_absent(local_connection, tmp_path):
    assert not local_connection.does_file_or_directory_exist(str(tmp_path / "nope"))


def test_write_overwrites_rather_than_appends(local_connection, tmp_path):
    target = str(tmp_path / "note.txt")
    local_connection.write_file(target, "first")
    local_connection.write_file(target, "second")

    assert local_connection.read_file(target) == "second"


###########################################################
# Directories
###########################################################

def test_make_directory_creates_it(local_connection, tmp_path):
    target = str(tmp_path / "nested" / "dir")
    local_connection.make_directory(target)

    assert os.path.isdir(target)
    assert local_connection.does_file_or_directory_exist(target)


def test_temporary_directory_is_real_and_writable(local_connection):
    temp_dir = local_connection.make_temporary_directory()

    assert temp_dir and os.path.isdir(temp_dir)
    probe = os.path.join(temp_dir, "probe")
    assert local_connection.write_file(probe, "ok")
    assert local_connection.read_file(probe) == "ok"

    local_connection.remove_file_or_directory(temp_dir)


###########################################################
# Moving, copying, removing
###########################################################

def test_copy_leaves_the_source_in_place(local_connection, tmp_path):
    source = str(tmp_path / "a.txt")
    destination = str(tmp_path / "b.txt")
    local_connection.write_file(source, "payload")

    local_connection.copy_file_or_directory(source, destination)

    assert local_connection.read_file(destination) == "payload"
    assert os.path.isfile(source), "copy must not consume the source"


def test_move_removes_the_source(local_connection, tmp_path):
    source = str(tmp_path / "a.txt")
    destination = str(tmp_path / "b.txt")
    local_connection.write_file(source, "payload")

    local_connection.move_file_or_directory(source, destination)

    assert local_connection.read_file(destination) == "payload"
    assert not os.path.exists(source)


def test_remove_deletes_a_file(local_connection, tmp_path):
    target = str(tmp_path / "a.txt")
    local_connection.write_file(target, "payload")

    local_connection.remove_file_or_directory(target)

    assert not os.path.exists(target)
    assert not local_connection.does_file_or_directory_exist(target)


def test_remove_deletes_a_directory_tree(local_connection, tmp_path):
    target = str(tmp_path / "tree")
    local_connection.make_directory(target)
    local_connection.write_file(os.path.join(target, "inner.txt"), "payload")

    local_connection.remove_file_or_directory(target)

    assert not os.path.exists(target)


###########################################################
# Permissions
###########################################################

def test_change_permission_applies_the_mode(local_connection, tmp_path):
    target = str(tmp_path / "secret.env")
    local_connection.write_file(target, "TOKEN=abc")

    local_connection.change_permission(target, "600")

    assert oct(os.stat(target).st_mode & 0o777) == "0o600"


###########################################################
# Commands
###########################################################

def test_run_output_returns_stdout(local_connection):
    assert "joybox" in local_connection.run_output(["echo", "joybox"])


def test_run_return_code_reports_success_and_failure(local_connection):
    assert local_connection.run_return_code(["true"]) == 0
    assert local_connection.run_return_code(["false"]) != 0


def test_run_checked_reflects_the_exit_status(local_connection):
    assert local_connection.run_checked(["true"]) is not False


###########################################################
# Pretend run
###########################################################

def test_pretend_run_touches_nothing(tmp_path):
    pretending = connection_local.ConnectionLocal(
        runoptions.RunFlags(verbose = False, pretend_run = True),
        runoptions.RunOptions())

    target = str(tmp_path / "should-not-exist.txt")
    pretending.write_file(target, "content")

    assert not os.path.exists(target), "pretend_run must not write to disk"
