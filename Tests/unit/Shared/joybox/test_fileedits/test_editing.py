# Imports

# Third-party imports
import pytest

# Local imports
from joybox import fileedits
from file_helpers import write
from fileops_helpers import read


###########################################################
# Header checks
###########################################################

@pytest.mark.parametrize("header,expected", [
    (b"PK\x03\x04", True),
    ("PK", True),
    (b"7z", False),
])
def test_header_is_compared_as_bytes(tmp_path, header, expected):
    path = tmp_path / "archive.zip"
    path.write_bytes(b"PK\x03\x04rest")
    assert fileedits.is_file_correctly_headered(str(path), header) is expected


def test_header_check_rejects_missing_files_and_directories(tmp_path):
    assert fileedits.is_file_correctly_headered(str(tmp_path / "missing"), b"PK") is False
    assert fileedits.is_file_correctly_headered(str(tmp_path), b"PK") is False


###########################################################
# File content modification
###########################################################

def test_replacements_apply_in_order(tmp_path):
    path = write(tmp_path / "config.ini", "root=$ROOT\nsave=$SAVE\n")
    assert fileedits.replace_strings_in_file(path, [
        {"from": "$ROOT", "to": "/games"},
        {"from": "$SAVE", "to": "/games/saves"},
    ])
    assert read(path) == "root=/games\nsave=/games/saves\n"


def test_replacements_with_an_empty_side_are_skipped(tmp_path):
    # Launching swaps tokens in and back out, so an empty save dir must not
    # erase the token it would later need to restore.
    path = write(tmp_path / "config.ini", "save=$SAVE\n")
    assert fileedits.replace_strings_in_file(path, [{"from": "$SAVE", "to": ""}, {"from": "", "to": "x"}])
    assert read(path) == "save=$SAVE\n"


def test_replacements_leave_the_file_alone_in_a_pretend_run(tmp_path):
    path = write(tmp_path / "config.ini", "a")
    assert fileedits.replace_strings_in_file(path, [{"from": "a", "to": "b"}], verbose = True, pretend_run = True)
    assert read(path) == "a"


def test_replacements_need_a_file(tmp_path):
    assert not fileedits.replace_strings_in_file(str(tmp_path), [], verbose = True)


def test_replacements_report_a_malformed_entry(tmp_path):
    path = write(tmp_path / "config.ini")
    assert not fileedits.replace_strings_in_file(path, [{"from": "x"}])
    with pytest.raises(SystemExit):
        fileedits.replace_strings_in_file(path, [{"from": "x"}], exit_on_failure = True)


def test_append_line_adds_a_missing_line(tmp_path):
    path = write(tmp_path / "list.txt", "one\n")
    assert fileedits.append_line_to_file(path, "two", verbose = True)
    assert read(path) == "one\ntwo\n"


def test_append_line_does_not_duplicate(tmp_path):
    path = write(tmp_path / "list.txt", "one\ntwo\n")
    assert fileedits.append_line_to_file(path, "one")
    assert read(path) == "one\ntwo\n"


def test_append_line_terminates_an_unfinished_last_line(tmp_path):
    path = write(tmp_path / "list.txt", "one")
    assert fileedits.append_line_to_file(path, "two")
    assert read(path) == "one\ntwo\n"


def test_append_line_to_an_empty_file(tmp_path):
    path = write(tmp_path / "list.txt", "")
    assert fileedits.append_line_to_file(path, "one")
    assert read(path) == "one\n"


def test_append_line_in_a_pretend_run(tmp_path):
    path = write(tmp_path / "list.txt", "one\n")
    assert fileedits.append_line_to_file(path, "two", pretend_run = True)
    assert read(path) == "one\n"


def test_append_line_keeps_the_files_line_endings(tmp_path):
    path = tmp_path / "list.txt"
    path.write_bytes(b"one\r\ntwo\r\n")
    assert fileedits.append_line_to_file(str(path), "three")
    assert path.read_bytes() == b"one\r\ntwo\r\nthree\n"


def test_append_line_finds_a_line_ended_by_a_carriage_return(tmp_path):
    path = tmp_path / "list.txt"
    path.write_bytes(b"one\rtwo\r")
    assert fileedits.append_line_to_file(str(path), "two")
    assert path.read_bytes() == b"one\rtwo\r"

def test_append_line_needs_a_file(tmp_path):
    assert not fileedits.append_line_to_file(str(tmp_path / "missing"), "one", verbose = True)


def test_append_line_reports_undecodable_contents(tmp_path):
    path = tmp_path / "list.txt"
    path.write_bytes(b"\xff\xfe\xfa")
    assert not fileedits.append_line_to_file(str(path), "one")
    with pytest.raises(SystemExit):
        fileedits.append_line_to_file(str(path), "one", exit_on_failure = True)


def test_sort_orders_lines(tmp_path):
    path = write(tmp_path / "list.txt", "c\na\nb\n")
    assert fileedits.sort_file_contents(path, verbose = True)
    assert read(path) == "a\nb\nc\n"


def test_sort_keeps_an_unterminated_last_line_separate(tmp_path):
    path = write(tmp_path / "list.txt", "b\na")
    assert fileedits.sort_file_contents(path)
    assert read(path) == "a\nb\n"


def test_sort_in_a_pretend_run(tmp_path):
    path = write(tmp_path / "list.txt", "b\na\n")
    assert fileedits.sort_file_contents(path, pretend_run = True)
    assert read(path) == "b\na\n"


def test_sort_needs_a_file(tmp_path):
    assert not fileedits.sort_file_contents(str(tmp_path), verbose = True)


def test_sort_reports_undecodable_contents(tmp_path):
    path = tmp_path / "list.txt"
    path.write_bytes(b"\xff\xfe\xfa")
    assert not fileedits.sort_file_contents(str(path))
    with pytest.raises(SystemExit):
        fileedits.sort_file_contents(str(path), exit_on_failure = True)


###########################################################
# Editing
###########################################################

def test_strings_are_replaced_in_place(tmp_path):
    target = write(str(tmp_path / "config.txt"), "host = old\nport = 1\n")

    assert fileedits.replace_strings_in_file(
        target, [{"from": "old", "to": "new"}]) is True
    assert "host = new" in read(target)


def test_several_replacements_all_apply(tmp_path):
    target = write(str(tmp_path / "config.txt"), "a b\n")

    fileedits.replace_strings_in_file(
        target, [{"from": "a", "to": "1"}, {"from": "b", "to": "2"}])

    assert read(target) == "1 2\n"


def test_replacing_in_a_missing_file_reports_failure(tmp_path):
    assert fileedits.replace_strings_in_file(
        str(tmp_path / "absent.txt"), [{"from": "a", "to": "b"}]) is False


def test_replacing_in_a_directory_reports_failure(tmp_path):
    assert fileedits.replace_strings_in_file(
        str(tmp_path), [{"from": "a", "to": "b"}]) is False


def test_a_line_is_appended(tmp_path):
    target = write(str(tmp_path / "log.txt"), "first\n")

    assert fileedits.append_line_to_file(target, "second") is True
    assert "first" in read(target)
    assert "second" in read(target)


def test_file_contents_are_sorted(tmp_path):
    target = write(str(tmp_path / "list.txt"), "c\na\nb\n")

    assert fileedits.sort_file_contents(target) is True
    assert read(target).split() == ["a", "b", "c"]


###########################################################
# Headers
#
# Used to tell a real archive from a file with the right extension.
###########################################################

def test_a_matching_byte_header_is_recognised(tmp_path):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK\x03\x04rest of the file")

    assert fileedits.is_file_correctly_headered(str(target), b"PK\x03\x04") is True


def test_a_header_that_is_neither_bytes_nor_text_never_matches(tmp_path):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK")

    assert fileedits.is_file_correctly_headered(str(target), [0x50, 0x4B]) is False


def test_a_matching_text_header_is_recognised(tmp_path):
    target = tmp_path / "script.sh"
    target.write_text("#!/bin/bash\necho hi\n")

    assert fileedits.is_file_correctly_headered(str(target), "#!/bin/bash") is True


def test_a_wrong_header_is_rejected(tmp_path):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"not an archive at all")

    assert fileedits.is_file_correctly_headered(str(target), b"PK\x03\x04") is False


def test_a_truncated_file_is_rejected(tmp_path):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK")

    assert fileedits.is_file_correctly_headered(str(target), b"PK\x03\x04") is False


def test_a_missing_file_has_no_header(tmp_path):
    assert fileedits.is_file_correctly_headered(str(tmp_path / "absent"), b"PK") is False


def test_a_directory_has_no_header(tmp_path):
    assert fileedits.is_file_correctly_headered(str(tmp_path), b"PK") is False
