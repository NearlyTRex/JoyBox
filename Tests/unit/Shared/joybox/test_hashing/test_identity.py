# Imports
import os
import zipfile

# Third-party imports
import pytest

# Local imports
from joybox import hashing
from hashing_helpers import write_file


###########################################################
# Telling files apart
#
# What decides whether an incoming file is already in the locker. A false
# "identical" drops a file that was actually different.
###########################################################

def build_zip(directory, name, members):
    path = os.path.join(str(directory), name)
    with zipfile.ZipFile(path, "w") as archive_file:
        for member, contents in sorted(members.items()):
            archive_file.writestr(member, contents)
    return path


###########################################################
# Plain files
###########################################################

def test_files_with_the_same_contents_are_identical(tmp_path):
    first = write_file(tmp_path, "first.bin", b"payload")
    second = write_file(tmp_path, "second.bin", b"payload")

    assert hashing.are_plain_files_identical(first, second) is True


def test_files_with_different_contents_are_not_identical(tmp_path):
    first = write_file(tmp_path, "first.bin", b"one")
    second = write_file(tmp_path, "second.bin", b"two")

    assert hashing.are_plain_files_identical(first, second) is False


def test_a_missing_file_is_never_identical(tmp_path):
    first = write_file(tmp_path, "first.bin", b"payload")
    absent = os.path.join(str(tmp_path), "absent.bin")

    assert hashing.are_plain_files_identical(first, absent) is False
    assert hashing.are_plain_files_identical(absent, first) is False


def test_two_missing_files_are_not_identical(tmp_path):
    # Both digest to the empty string, which must not read as a match
    first = os.path.join(str(tmp_path), "one.bin")
    second = os.path.join(str(tmp_path), "two.bin")

    assert hashing.are_plain_files_identical(first, second) is False


def test_a_file_is_identical_to_itself(tmp_path):
    path = write_file(tmp_path, "one.bin", b"payload")

    assert hashing.are_plain_files_identical(path, path) is True


def test_empty_files_are_identical(tmp_path):
    first = write_file(tmp_path, "first.bin", b"")
    second = write_file(tmp_path, "second.bin", b"")

    assert hashing.are_plain_files_identical(first, second) is True


###########################################################
# Archives
#
# Compared by what they contain, so two archives built at different times
# from the same files still match.
###########################################################

def test_archives_with_the_same_members_are_identical(tmp_path):
    first = build_zip(tmp_path, "first.zip", {"a.txt": "one", "b.txt": "two"})
    second = build_zip(tmp_path, "second.zip", {"a.txt": "one", "b.txt": "two"})

    assert hashing.are_archive_files_identical(first, second) is True


def test_archives_with_different_member_contents_are_not_identical(tmp_path):
    first = build_zip(tmp_path, "first.zip", {"a.txt": "one"})
    second = build_zip(tmp_path, "second.zip", {"a.txt": "different"})

    assert hashing.are_archive_files_identical(first, second) is False


def test_archives_with_different_member_names_are_not_identical(tmp_path):
    first = build_zip(tmp_path, "first.zip", {"a.txt": "one"})
    second = build_zip(tmp_path, "second.zip", {"b.txt": "one"})

    assert hashing.are_archive_files_identical(first, second) is False


def test_an_extra_member_makes_archives_different(tmp_path):
    first = build_zip(tmp_path, "first.zip", {"a.txt": "one"})
    second = build_zip(tmp_path, "second.zip", {"a.txt": "one", "b.txt": "two"})

    assert hashing.are_archive_files_identical(first, second) is False


def test_member_order_does_not_make_archives_different(tmp_path):
    first = build_zip(tmp_path, "first.zip", {"a.txt": "one", "b.txt": "two"})
    second = os.path.join(str(tmp_path), "second.zip")
    with zipfile.ZipFile(second, "w") as archive_file:
        archive_file.writestr("b.txt", "two")
        archive_file.writestr("a.txt", "one")

    assert hashing.are_archive_files_identical(first, second) is True


def test_empty_archives_are_not_reported_as_identical(tmp_path):
    # Nothing to compare is not evidence of a match
    first = build_zip(tmp_path, "first.zip", {})
    second = build_zip(tmp_path, "second.zip", {})

    assert hashing.are_archive_files_identical(first, second) is False


def test_a_plain_file_is_not_compared_as_an_archive(tmp_path):
    first = write_file(tmp_path, "first.bin", b"payload")
    second = write_file(tmp_path, "second.bin", b"payload")

    assert hashing.are_archive_files_identical(first, second) is False


###########################################################
# Either kind
###########################################################

def test_identical_plain_files_satisfy_the_general_check(tmp_path):
    first = write_file(tmp_path, "first.bin", b"payload")
    second = write_file(tmp_path, "second.bin", b"payload")

    assert hashing.are_files_identical(first, second) is True


def test_archives_matching_only_by_content_satisfy_the_general_check(tmp_path):
    # Repacking stamps a new time into the member header, so the bytes differ
    # while the members do not
    first = build_zip(tmp_path, "first.zip", {"a.txt": "one"})
    second = os.path.join(str(tmp_path), "second.zip")
    with zipfile.ZipFile(second, "w") as archive_file:
        member = zipfile.ZipInfo("a.txt", date_time = (2020, 1, 1, 0, 0, 0))
        archive_file.writestr(member, "one")

    assert hashing.are_plain_files_identical(first, second) is False
    assert hashing.are_files_identical(first, second) is True


def test_different_files_satisfy_neither_check(tmp_path):
    first = write_file(tmp_path, "first.bin", b"one")
    second = write_file(tmp_path, "second.bin", b"two")

    assert hashing.are_files_identical(first, second) is False


###########################################################
# Finding duplicates in a directory
###########################################################

def test_a_duplicate_in_the_directory_is_found(tmp_path):
    source = write_file(tmp_path, "source.bin", b"payload")
    search = tmp_path / "search"
    search.mkdir()
    copy = write_file(search, "copy.bin", b"payload")
    write_file(search, "other.bin", b"different")

    found = hashing.find_duplicate_files(source, str(search))

    assert found == [copy]


def test_a_directory_with_no_duplicates_finds_nothing(tmp_path):
    source = write_file(tmp_path, "source.bin", b"payload")
    search = tmp_path / "search"
    search.mkdir()
    write_file(search, "other.bin", b"different")

    assert hashing.find_duplicate_files(source, str(search)) == []


def test_subdirectories_are_not_searched_for_duplicates(tmp_path):
    source = write_file(tmp_path, "source.bin", b"payload")
    search = tmp_path / "search"
    (search / "nested").mkdir(parents = True)
    write_file(search / "nested", "copy.bin", b"payload")

    assert hashing.find_duplicate_files(source, str(search)) == []


def test_a_duplicate_archive_is_found_by_its_members(tmp_path):
    source = build_zip(tmp_path, "source.zip", {"a.txt": "one"})
    search = tmp_path / "search"
    search.mkdir()
    copy = build_zip(search, "copy.zip", {"a.txt": "one"})

    assert hashing.find_duplicate_archives(source, str(search)) == [copy]


def test_an_archive_with_other_members_is_not_a_duplicate(tmp_path):
    source = build_zip(tmp_path, "source.zip", {"a.txt": "one"})
    search = tmp_path / "search"
    search.mkdir()
    build_zip(search, "other.zip", {"b.txt": "two"})

    assert hashing.find_duplicate_archives(source, str(search)) == []


###########################################################
# How a member checksum is rendered
###########################################################

def test_a_member_checksum_is_rendered_like_a_dat_entry(tmp_path):
    path = build_zip(tmp_path, "one.zip", {"a.txt": "one"})

    from joybox import archive

    crc = archive.get_archive_checksums(path)[0]["crc"]
    assert len(crc) == 8
    assert not crc.startswith("0x")
    assert crc == crc.lower()


def test_a_member_checksum_matches_the_same_bytes_on_disk(tmp_path):
    # Both are a crc32 of the uncompressed contents, so the two sides of the
    # codebase have to render one the same way
    from joybox import archive

    payload = b"the member payload"
    loose = write_file(tmp_path, "a.txt", payload)
    packed = build_zip(tmp_path, "one.zip", {"a.txt": payload.decode()})

    assert archive.get_archive_checksums(packed)[0]["crc"] == hashing.calculate_file_crc32(loose)
