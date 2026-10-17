# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import runoptions
from joybox.connection import connection_local
from connection_local_helpers import only


###########################################################
# Delegating to the shared primitives
###########################################################

def test_an_unprivileged_directory_is_made_through_fileops(connection, delegated):
    connection.make_directory("/tmp/app")

    assert only(delegated, "make_directory")["args"] == ("/tmp/app",)


def test_an_unprivileged_write_is_a_touch(connection, delegated):
    connection.write_file("/tmp/app.conf", "contents")

    assert only(delegated, "touch_file")["kwargs"]["contents"] == "contents"


def test_an_unprivileged_link_is_a_symlink(connection, delegated):
    connection.link_file_or_directory("/tmp/target", "/tmp/link")

    assert only(delegated, "create_symlink")["args"] == ("/tmp/target", "/tmp/link")


def test_an_unprivileged_extract_goes_through_the_archiver(connection, delegated):
    connection.extract_tar_archive("/tmp/app.tar.gz", "/tmp/app")

    assert only(delegated, "extract_archive")["args"] == ("/tmp/app.tar.gz", "/tmp/app")


def test_an_unprivileged_download_goes_through_the_network(connection, delegated):
    connection.download_file("https://example.test/app.tar", "/tmp/app.tar")

    assert only(delegated, "download_url")["kwargs"]["output_file"] == "/tmp/app.tar"


def test_a_transfer_passes_its_excludes(connection, delegated):
    connection.transfer_files("/tmp/src", "/tmp/dest", excludes = ["*.log"])

    assert only(delegated, "copy_file_or_directory")["kwargs"]["excludes"] == ["*.log"]


@pytest.mark.parametrize("method,args,delegate", [
    ("make_directory", ("/tmp/app",), "make_directory"),
    ("remove_file_or_directory", ("/tmp/app",), "remove_file_or_directory"),
    ("move_file_or_directory", ("/tmp/a", "/tmp/b"), "move_file_or_directory"),
    ("copy_file_or_directory", ("/tmp/a", "/tmp/b"), "copy_file_or_directory"),
    ("write_file", ("/tmp/a", "contents"), "touch_file"),
])
def test_the_connections_flags_reach_the_primitive(connection, delegated, method, args, delegate):
    # A dry run that reaches fileops without pretend_run set writes for real.
    connection.flags.pretend_run = True
    connection.flags.verbose = True

    getattr(connection, method)(*args)
    passed = only(delegated, delegate)["kwargs"]

    assert passed["pretend_run"] is True
    assert passed["verbose"] is True
    assert passed["exit_on_failure"] is False


###########################################################
# Dry runs
###########################################################

def test_pretending_makes_no_temporary_directory(pretending):
    assert pretending.make_temporary_directory() is None


def test_a_temporary_directory_is_real(connection):
    from joybox import fileops

    temp_dir = connection.make_temporary_directory()

    assert os.path.isdir(temp_dir)
    fileops.remove_directory(temp_dir)


def test_a_failed_temporary_directory_is_reported(connection, monkeypatch):
    monkeypatch.setattr(
        connection_local.fileops, "create_temporary_directory",
        lambda **kwargs: (False, "no space"))

    assert connection.make_temporary_directory() is None


def test_pretending_assumes_paths_exist(pretending, tmp_path):
    # A dry run reports what a real run would do next, and a real run would
    # have created the path by then.
    assert pretending.does_file_or_directory_exist(str(tmp_path / "absent")) is True


def test_an_existing_path_is_found(connection, tmp_path):
    assert connection.does_file_or_directory_exist(str(tmp_path)) is True


def test_a_missing_path_is_not_found(connection, tmp_path):
    assert connection.does_file_or_directory_exist(str(tmp_path / "absent")) is False


def test_pretending_reads_nothing(pretending, tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("data")

    assert pretending.read_file(str(target)) is None


def test_reading_a_missing_file_yields_nothing(connection, tmp_path):
    assert connection.read_file(str(tmp_path / "absent.txt")) is None


def test_a_read_error_can_quit_the_program(tmp_path):
    strict = connection_local.ConnectionLocal(
        runoptions.RunFlags(verbose = False, exit_on_failure = True),
        runoptions.RunOptions())

    with pytest.raises(SystemExit):
        strict.read_file(str(tmp_path / "absent.txt"))
