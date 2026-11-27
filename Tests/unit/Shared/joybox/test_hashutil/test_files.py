# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import hashutil


###########################################################
# File hashing
#
# Collection dedup and the backup hash sidecars both rest on these, so a
# changed digest format or a false "identical" silently loses files.
###########################################################

HELLO_VECTORS = {
    "crc32": "3610a686",
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
}


def write(path, contents = b"hello"):
    with open(path, "wb") as handle:
        handle.write(contents)
    return path


def hasher(algorithm):
    return getattr(hashutil, f"calculate_file_{algorithm}")


@pytest.mark.parametrize("algorithm,expected", sorted(HELLO_VECTORS.items()))
def test_file_digests_match_known_vectors(algorithm, expected, tmp_path):
    target = write(str(tmp_path / "a.bin"))
    assert hasher(algorithm)(target) == expected


@pytest.mark.parametrize("algorithm", sorted(HELLO_VECTORS))
def test_a_missing_file_hashes_to_empty(algorithm, tmp_path):
    assert hasher(algorithm)(str(tmp_path / "absent.bin")) == ""


@pytest.mark.parametrize("algorithm", sorted(HELLO_VECTORS))
def test_pretend_run_hashes_nothing(algorithm, tmp_path):
    target = write(str(tmp_path / "a.bin"))
    assert hasher(algorithm)(target, pretend_run = True) == ""


@pytest.mark.parametrize("algorithm", sorted(HELLO_VECTORS))
def test_an_empty_file_still_hashes(algorithm, tmp_path):
    target = write(str(tmp_path / "empty.bin"), b"")
    assert hasher(algorithm)(target) != ""


def test_chunking_does_not_change_the_digest(tmp_path):
    # Files are read in chunks, so the digest must not depend on the size.
    target = write(str(tmp_path / "big.bin"), b"x" * 100000)

    assert hashutil.calculate_file_crc32(target, chunksize = 7) == \
        hashutil.calculate_file_crc32(target, chunksize = 65536)


def test_different_contents_hash_differently(tmp_path):
    first = write(str(tmp_path / "a.bin"), b"content a")
    second = write(str(tmp_path / "b.bin"), b"content b")

    assert hashutil.calculate_file_crc32(first) != hashutil.calculate_file_crc32(second)


###########################################################
# Identity
###########################################################

def test_identical_contents_are_identical(tmp_path):
    first = write(str(tmp_path / "a.bin"), b"same")
    second = write(str(tmp_path / "b.bin"), b"same")

    assert hashutil.are_plain_files_identical(first, second) is True
    assert hashutil.are_files_identical(first, second) is True


def test_differing_contents_are_not_identical(tmp_path):
    first = write(str(tmp_path / "a.bin"), b"one")
    second = write(str(tmp_path / "b.bin"), b"two")

    assert hashutil.are_plain_files_identical(first, second) is False
    assert hashutil.are_files_identical(first, second) is False


def test_a_missing_side_is_never_identical(tmp_path):
    existing = write(str(tmp_path / "a.bin"))

    assert hashutil.are_plain_files_identical(existing, str(tmp_path / "absent.bin")) is False
    assert hashutil.are_plain_files_identical(str(tmp_path / "absent.bin"), existing) is False


def test_a_file_is_identical_to_itself(tmp_path):
    target = write(str(tmp_path / "a.bin"))
    assert hashutil.are_plain_files_identical(target, target) is True


def test_two_empty_files_are_identical(tmp_path):
    first = write(str(tmp_path / "a.bin"), b"")
    second = write(str(tmp_path / "b.bin"), b"")

    assert hashutil.are_plain_files_identical(first, second) is True


###########################################################
# Duplicates
###########################################################

def test_duplicates_are_found_in_a_directory(tmp_path):
    needle = write(str(tmp_path / "needle.bin"), b"payload")
    search = tmp_path / "search"
    search.mkdir()
    write(str(search / "copy.bin"), b"payload")
    write(str(search / "other.bin"), b"different")

    found = hashutil.find_duplicate_files(needle, str(search))

    assert [os.path.basename(path) for path in found] == ["copy.bin"]


def test_every_duplicate_is_reported(tmp_path):
    needle = write(str(tmp_path / "needle.bin"), b"payload")
    search = tmp_path / "search"
    search.mkdir()
    write(str(search / "one.bin"), b"payload")
    write(str(search / "two.bin"), b"payload")

    found = hashutil.find_duplicate_files(needle, str(search))

    assert sorted(os.path.basename(path) for path in found) == ["one.bin", "two.bin"]


def test_no_duplicates_returns_empty(tmp_path):
    needle = write(str(tmp_path / "needle.bin"), b"payload")
    search = tmp_path / "search"
    search.mkdir()
    write(str(search / "other.bin"), b"different")

    assert hashutil.find_duplicate_files(needle, str(search)) == []


def test_subdirectories_are_not_searched(tmp_path):
    # get_directory_contents lists one level only.
    needle = write(str(tmp_path / "needle.bin"), b"payload")
    search = tmp_path / "search"
    (search / "nested").mkdir(parents = True)
    write(str(search / "nested" / "copy.bin"), b"payload")

    assert hashutil.find_duplicate_files(needle, str(search)) == []
