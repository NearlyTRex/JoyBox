# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import fileedits


###########################################################
# What fileedits does when the filesystem says no
#
# Every edit takes exit_on_failure, and the collection relies on the
# difference: a batch run carries on past one bad file, a setup run stops.
# An edit that reports success after failing leaves a config the caller
# believes was changed.
###########################################################

pytestmark = pytest.mark.skipif(
    os.geteuid() == 0, reason = "root ignores the permissions these rely on")


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
    assert fileedits.replace_strings_in_file(
        read_only_file, [{"from": "data", "to": "other"}]) is False


def test_appending_to_a_file_that_cannot_be_written_reports_failure(read_only_file):
    assert fileedits.append_line_to_file(read_only_file, "a line") is False


def test_sorting_a_file_that_cannot_be_written_reports_failure(read_only_file):
    assert fileedits.sort_file_contents(read_only_file) is False


def test_a_failed_edit_leaves_the_contents_alone(read_only_file):
    fileedits.replace_strings_in_file(read_only_file, [{"from": "data", "to": "other"}])

    with open(read_only_file, encoding = "utf-8") as handle:
        assert handle.read() == "data\n"



@pytest.fixture
def unreadable_file(tmp_path):
    target = tmp_path / "unreadable.txt"
    target.write_text("data\n")
    os.chmod(str(target), 0o200)
    yield str(target)
    os.chmod(str(target), 0o600)


@pytest.mark.parametrize("operation,args", [
    ("replace_strings_in_file", ([{"from": "data", "to": "other"}],)),
    ("append_line_to_file", ("a line",)),
    ("sort_file_contents", ()),
])
def test_editing_a_file_that_cannot_be_read_reports_failure(unreadable_file, operation, args):
    assert getattr(fileedits, operation)(unreadable_file, *args) is False
    with pytest.raises(SystemExit):
        getattr(fileedits, operation)(unreadable_file, *args, exit_on_failure = True)

@pytest.mark.parametrize("operation,args", [
    ("replace_strings_in_file", ([{"from": "a", "to": "b"}],)),
    ("append_line_to_file", ("a line",)),
    ("sort_file_contents", ()),
])
def test_editing_a_missing_file_reports_failure(tmp_path, operation, args):
    assert getattr(fileedits, operation)(str(tmp_path / "absent.txt"), *args) is False
