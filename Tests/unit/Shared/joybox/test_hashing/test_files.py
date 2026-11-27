# Imports
import json

# Local imports
from joybox import hashing


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
    with open(path, "w", encoding = "utf-8") as handle:
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
