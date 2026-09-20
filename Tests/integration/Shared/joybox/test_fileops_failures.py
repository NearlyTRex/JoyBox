# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import fileops


###########################################################
# What fileops does when the filesystem says no
#
# Every operation takes exit_on_failure, and the collection relies on the
# difference: a batch run carries on past one bad file, a setup run stops.
# An operation that reports success after failing is the dangerous case,
# because the caller then removes the source.
###########################################################

pytestmark = pytest.mark.skipif(
    os.geteuid() == 0, reason = "root ignores the permissions these rely on")


@pytest.fixture
def unwritable(tmp_path):
    # A directory nothing may be written into, restored afterwards so pytest
    # can clean up.
    target = tmp_path / "locked"
    target.mkdir()
    (target / "existing.txt").write_text("data")
    os.chmod(str(target), 0o500)
    yield target
    os.chmod(str(target), 0o700)


@pytest.fixture
def source_file(tmp_path):
    target = tmp_path / "source.txt"
    target.write_text("payload")
    return str(target)


###########################################################
# Creating
###########################################################

def test_a_file_that_cannot_be_written_reports_failure(unwritable):
    assert fileops.touch_file(str(unwritable / "new.txt")) is False


def test_a_file_that_cannot_be_written_can_quit_the_program(unwritable):
    with pytest.raises(SystemExit):
        fileops.touch_file(str(unwritable / "new.txt"), exit_on_failure = True)


def test_a_directory_that_cannot_be_made_reports_failure(unwritable):
    assert fileops.make_directory(str(unwritable / "sub")) is False


def test_a_directory_that_cannot_be_made_can_quit_the_program(unwritable):
    with pytest.raises(SystemExit):
        fileops.make_directory(str(unwritable / "sub"), exit_on_failure = True)


def test_a_symlink_that_cannot_be_made_reports_failure(unwritable, source_file):
    assert fileops.create_symlink(source_file, str(unwritable / "link.txt")) is False


def test_a_symlink_that_cannot_be_made_can_quit_the_program(unwritable, source_file):
    with pytest.raises(SystemExit):
        fileops.create_symlink(
            source_file, str(unwritable / "link.txt"), exit_on_failure = True)


###########################################################
# Removing
###########################################################

def test_a_file_that_cannot_be_removed_reports_failure(unwritable):
    assert fileops.remove_file(str(unwritable / "existing.txt")) is False


def test_a_file_that_cannot_be_removed_can_quit_the_program(unwritable):
    with pytest.raises(SystemExit):
        fileops.remove_file(str(unwritable / "existing.txt"), exit_on_failure = True)


def test_a_directory_that_cannot_be_emptied_reports_failure(unwritable):
    assert fileops.remove_directory_contents(str(unwritable)) is False


def test_a_directory_that_cannot_be_emptied_can_quit_the_program(unwritable):
    with pytest.raises(SystemExit):
        fileops.remove_directory_contents(str(unwritable), exit_on_failure = True)


def test_removing_a_directory_that_is_already_gone_is_success(tmp_path):
    # Removal is idempotent; a directory that is not there is the state the
    # caller asked for, and a cleanup pass runs over paths twice.
    assert fileops.remove_directory(str(tmp_path / "absent")) is True


###########################################################
# Copying and moving
###########################################################

def test_a_copy_into_an_unwritable_place_reports_failure(unwritable, source_file):
    assert fileops.copy_file_or_directory(
        source_file, str(unwritable / "copy.txt")) is False


def test_a_copy_into_an_unwritable_place_can_quit_the_program(unwritable, source_file):
    with pytest.raises(SystemExit):
        fileops.copy_file_or_directory(
            source_file, str(unwritable / "copy.txt"), exit_on_failure = True)


def test_a_failed_copy_leaves_the_source(unwritable, source_file):
    fileops.copy_file_or_directory(source_file, str(unwritable / "copy.txt"))

    assert os.path.isfile(source_file)


def test_a_move_into_an_unwritable_place_reports_failure(unwritable, source_file):
    assert fileops.move_file_or_directory(
        source_file, str(unwritable / "moved.txt")) is False


def test_a_failed_move_leaves_the_source_where_it_was(unwritable, source_file):
    # This is the case that loses data: reporting success would have the
    # caller believe the file is now somewhere it never arrived.
    fileops.move_file_or_directory(source_file, str(unwritable / "moved.txt"))

    assert os.path.isfile(source_file)


def test_a_move_into_an_unwritable_place_can_quit_the_program(unwritable, source_file):
    with pytest.raises(SystemExit):
        fileops.move_file_or_directory(
            source_file, str(unwritable / "moved.txt"), exit_on_failure = True)


def test_copying_a_missing_source_reports_failure(tmp_path):
    assert fileops.copy_file_or_directory(
        str(tmp_path / "absent.txt"), str(tmp_path / "copy.txt")) is False


def test_moving_a_missing_source_reports_failure(tmp_path):
    assert fileops.move_file_or_directory(
        str(tmp_path / "absent.txt"), str(tmp_path / "moved.txt")) is False


###########################################################
# Editing
###########################################################

@pytest.fixture
def read_only_file(tmp_path):
    # Editing happens in place, so it is the file's own mode that stops it
    # rather than the directory's.
    target = tmp_path / "read-only.txt"
    target.write_text("data\n")
    os.chmod(str(target), 0o400)
    yield str(target)
    os.chmod(str(target), 0o600)


def test_editing_a_file_that_cannot_be_written_reports_failure(read_only_file):
    assert fileops.replace_strings_in_file(
        read_only_file, [{"from": "data", "to": "other"}]) is False


def test_appending_to_a_file_that_cannot_be_written_reports_failure(read_only_file):
    assert fileops.append_line_to_file(read_only_file, "a line") is False


def test_sorting_a_file_that_cannot_be_written_reports_failure(read_only_file):
    assert fileops.sort_file_contents(read_only_file) is False


def test_a_failed_edit_leaves_the_contents_alone(read_only_file):
    fileops.replace_strings_in_file(read_only_file, [{"from": "data", "to": "other"}])

    with open(read_only_file) as handle:
        assert handle.read() == "data\n"


@pytest.mark.parametrize("operation,args", [
    ("replace_strings_in_file", ([{"from": "a", "to": "b"}],)),
    ("append_line_to_file", ("a line",)),
    ("sort_file_contents", ()),
])
def test_editing_a_missing_file_reports_failure(tmp_path, operation, args):
    assert getattr(fileops, operation)(str(tmp_path / "absent.txt"), *args) is False


###########################################################
# Permissions
###########################################################

def test_changing_permissions_on_a_missing_path_reports_failure(tmp_path):
    # Nothing can carry the permissions, so reporting success would tell the
    # caller its file is now readable when there is no file.
    assert fileops.chmod_file_or_directory(str(tmp_path / "absent.txt"), 755) is False


def test_changing_permissions_on_a_missing_path_can_quit_the_program(tmp_path):
    with pytest.raises(SystemExit):
        fileops.chmod_file_or_directory(
            str(tmp_path / "absent.txt"), 755, exit_on_failure = True)


def test_pretending_to_change_permissions_on_a_missing_path_is_success(tmp_path):
    # A dry run reports what a real run would do, and by then an earlier step
    # would have created the path.
    assert fileops.chmod_file_or_directory(
        str(tmp_path / "absent.txt"), 755, pretend_run = True) is True


def test_a_bad_permission_string_reports_failure(tmp_path, source_file):
    assert fileops.chmod_file_or_directory(source_file, "not-octal") is False


def test_a_bad_permission_string_can_quit_the_program(tmp_path, source_file):
    with pytest.raises(SystemExit):
        fileops.chmod_file_or_directory(source_file, "not-octal", exit_on_failure = True)


def test_marking_a_missing_file_executable_reports_failure(tmp_path):
    assert fileops.mark_as_executable(str(tmp_path / "absent.txt")) is False


###########################################################
# Verbose runs
#
# Every operation logs what it is about to do when asked. The logging reads
# the same arguments the operation does, so a wrong format string there fails
# only on the runs someone is watching.
###########################################################

def test_a_verbose_run_creates_the_same_file(tmp_path):
    target = str(tmp_path / "new.txt")

    assert fileops.touch_file(target, contents = "data", verbose = True) is True
    assert os.path.isfile(target)


def test_a_verbose_run_makes_the_same_directory(tmp_path):
    target = str(tmp_path / "a" / "b")

    assert fileops.make_directory(target, verbose = True) is True
    assert os.path.isdir(target)


def test_a_verbose_copy_produces_the_same_file(tmp_path, source_file):
    target = str(tmp_path / "copy.txt")

    assert fileops.copy_file_or_directory(source_file, target, verbose = True) is True
    assert os.path.isfile(target)


def test_a_verbose_move_produces_the_same_file(tmp_path, source_file):
    target = str(tmp_path / "moved.txt")

    assert fileops.move_file_or_directory(source_file, target, verbose = True) is True
    assert os.path.isfile(target)
    assert not os.path.exists(source_file)


def test_a_verbose_transfer_produces_the_same_file(tmp_path, source_file):
    target = str(tmp_path / "transferred.txt")

    assert fileops.transfer_file(source_file, target, verbose = True) is True
    with open(target) as handle:
        assert handle.read() == "payload"


def test_a_verbose_removal_removes_the_same_file(tmp_path, source_file):
    assert fileops.remove_file(source_file, verbose = True) is True
    assert not os.path.exists(source_file)


def test_a_verbose_symlink_resolves_the_same_way(tmp_path, source_file):
    link = str(tmp_path / "link.txt")

    assert fileops.create_symlink(source_file, link, verbose = True) is True
    assert fileops.resolve_symlink(link, verbose = True) == os.path.realpath(source_file)


def test_a_verbose_edit_changes_the_same_contents(tmp_path, source_file):
    fileops.replace_strings_in_file(
        source_file, [{"from": "payload", "to": "replaced"}], verbose = True)

    with open(source_file) as handle:
        assert handle.read() == "replaced"


def test_a_verbose_append_adds_the_same_line(tmp_path, source_file):
    fileops.append_line_to_file(source_file, "a line", verbose = True)

    with open(source_file) as handle:
        assert "a line" in handle.read()


def test_a_verbose_sort_orders_the_same_way(tmp_path):
    target = tmp_path / "list.txt"
    target.write_text("b\na\n")

    fileops.sort_file_contents(str(target), verbose = True)

    assert target.read_text() == "a\nb\n"


def test_a_verbose_chmod_applies_the_same_permissions(tmp_path, source_file):
    import stat

    assert fileops.chmod_file_or_directory(source_file, 755, verbose = True) is True
    assert bool(os.stat(source_file).st_mode & stat.S_IXUSR)


def test_a_verbose_empty_leaves_the_directory(tmp_path):
    target = tmp_path / "tree"
    target.mkdir()
    (target / "file.txt").write_text("data")

    assert fileops.remove_directory_contents(str(target), verbose = True) is True
    assert target.is_dir()
    assert list(target.iterdir()) == []


def test_a_verbose_sync_mirrors_the_same_way(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "file.txt").write_text("data")
    dest = tmp_path / "dest"

    assert fileops.sync_contents(str(source), str(dest), verbose = True) is True
    assert (dest / "file.txt").read_text() == "data"


def test_a_verbose_temporary_directory_is_still_usable():
    created, temp_dir = fileops.create_temporary_directory(verbose = True)

    assert created is True
    assert os.path.isdir(temp_dir)

    fileops.remove_directory(temp_dir)


def test_a_verbose_temporary_file_is_still_usable():
    created, temp_file = fileops.create_temporary_file(verbose = True)

    assert created is True
    assert os.path.isfile(temp_file)

    fileops.remove_file(temp_file)
