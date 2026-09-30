# Imports
import json
import os

# Third-party imports
import pytest

# Local imports
from joybox import hashing


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
    return getattr(hashing, f"calculate_file_{algorithm}")


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

    assert hashing.calculate_file_crc32(target, chunksize = 7) == \
        hashing.calculate_file_crc32(target, chunksize = 65536)


def test_different_contents_hash_differently(tmp_path):
    first = write(str(tmp_path / "a.bin"), b"content a")
    second = write(str(tmp_path / "b.bin"), b"content b")

    assert hashing.calculate_file_crc32(first) != hashing.calculate_file_crc32(second)


###########################################################
# Identity
###########################################################

def test_identical_contents_are_identical(tmp_path):
    first = write(str(tmp_path / "a.bin"), b"same")
    second = write(str(tmp_path / "b.bin"), b"same")

    assert hashing.are_plain_files_identical(first, second) is True
    assert hashing.are_files_identical(first, second) is True


def test_differing_contents_are_not_identical(tmp_path):
    first = write(str(tmp_path / "a.bin"), b"one")
    second = write(str(tmp_path / "b.bin"), b"two")

    assert hashing.are_plain_files_identical(first, second) is False
    assert hashing.are_files_identical(first, second) is False


def test_a_missing_side_is_never_identical(tmp_path):
    existing = write(str(tmp_path / "a.bin"))

    assert hashing.are_plain_files_identical(existing, str(tmp_path / "absent.bin")) is False
    assert hashing.are_plain_files_identical(str(tmp_path / "absent.bin"), existing) is False


def test_a_file_is_identical_to_itself(tmp_path):
    target = write(str(tmp_path / "a.bin"))
    assert hashing.are_plain_files_identical(target, target) is True


def test_two_empty_files_are_identical(tmp_path):
    first = write(str(tmp_path / "a.bin"), b"")
    second = write(str(tmp_path / "b.bin"), b"")

    assert hashing.are_plain_files_identical(first, second) is True


###########################################################
# Duplicates
###########################################################

def test_duplicates_are_found_in_a_directory(tmp_path):
    needle = write(str(tmp_path / "needle.bin"), b"payload")
    search = tmp_path / "search"
    search.mkdir()
    write(str(search / "copy.bin"), b"payload")
    write(str(search / "other.bin"), b"different")

    found = hashing.find_duplicate_files(needle, str(search))

    assert [os.path.basename(path) for path in found] == ["copy.bin"]


def test_every_duplicate_is_reported(tmp_path):
    needle = write(str(tmp_path / "needle.bin"), b"payload")
    search = tmp_path / "search"
    search.mkdir()
    write(str(search / "one.bin"), b"payload")
    write(str(search / "two.bin"), b"payload")

    found = hashing.find_duplicate_files(needle, str(search))

    assert sorted(os.path.basename(path) for path in found) == ["one.bin", "two.bin"]


def test_no_duplicates_returns_empty(tmp_path):
    needle = write(str(tmp_path / "needle.bin"), b"payload")
    search = tmp_path / "search"
    search.mkdir()
    write(str(search / "other.bin"), b"different")

    assert hashing.find_duplicate_files(needle, str(search)) == []


def test_subdirectories_are_not_searched(tmp_path):
    # get_directory_contents lists one level only.
    needle = write(str(tmp_path / "needle.bin"), b"payload")
    search = tmp_path / "search"
    (search / "nested").mkdir(parents = True)
    write(str(search / "nested" / "copy.bin"), b"payload")

    assert hashing.find_duplicate_files(needle, str(search)) == []


###########################################################
# Grouping
###########################################################

def write_hash_file(path, entries):
    # Sidecar shape: a list of {dir, filename, hash, size, mtime} records.
    records = [
        {
            "dir": directory,
            "filename": filename,
            "hash": "0" * 16,
            "size": str(size),
            "mtime": "0",
        }
        for directory, filename, size in entries
    ]
    with open(path, "w") as handle:
        handle.write(json.dumps(records))
    return path


def test_files_under_the_limit_share_one_group(tmp_path):
    sidecar = write_hash_file(str(tmp_path / "a.json"), [
        ("dir", "one.bin", 10),
        ("dir", "two.bin", 20),
    ])

    groups = hashing.get_file_groupings([sidecar], max_group_size = 1000)

    assert len(groups) == 1
    assert groups["Group1"]["size"] == 30
    assert len(groups["Group1"]["files"]) == 2


def test_a_group_splits_when_the_limit_is_exceeded(tmp_path):
    sidecar = write_hash_file(str(tmp_path / "a.json"), [
        ("alpha", "one.bin", 600),
        ("beta", "two.bin", 600),
    ])

    groups = hashing.get_file_groupings([sidecar], max_group_size = 1000)

    assert len(groups) == 2


def test_files_in_one_directory_stay_together(tmp_path):
    # A directory is the indivisible unit, even when it exceeds the limit.
    sidecar = write_hash_file(str(tmp_path / "a.json"), [
        ("dir", "one.bin", 900),
        ("dir", "two.bin", 900),
    ])

    groups = hashing.get_file_groupings([sidecar], max_group_size = 1000)

    assert len(groups) == 1
    assert len(groups["Group1"]["files"]) == 2


def test_an_oversized_directory_does_not_leave_an_empty_group(tmp_path):
    # Splitting on an empty group orphans it and every consumer sees it.
    sidecar = write_hash_file(str(tmp_path / "a.json"), [("dir", "big.bin", 5000)])

    groups = hashing.get_file_groupings([sidecar], max_group_size = 1000)

    assert all(group["files"] for group in groups.values())


def test_an_oversized_directory_still_splits_from_a_filled_group(tmp_path):
    sidecar = write_hash_file(str(tmp_path / "a.json"), [
        ("alpha", "small.bin", 10),
        ("beta", "big.bin", 5000),
    ])

    groups = hashing.get_file_groupings([sidecar], max_group_size = 1000)

    assert len(groups) == 2
    assert all(group["files"] for group in groups.values())


def test_several_sidecars_are_combined(tmp_path):
    first = write_hash_file(str(tmp_path / "a.json"), [("alpha", "one.bin", 10)])
    second = write_hash_file(str(tmp_path / "b.json"), [("beta", "two.bin", 20)])

    groups = hashing.get_file_groupings([first, second], max_group_size = 1000)

    assert groups["Group1"]["size"] == 30


def test_grouping_no_files_yields_one_empty_group(tmp_path):
    sidecar = write_hash_file(str(tmp_path / "a.json"), [])

    groups = hashing.get_file_groupings([sidecar], max_group_size = 1000)

    assert groups == {"Group1": {"size": 0, "files": []}}
