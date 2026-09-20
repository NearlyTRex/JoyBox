# Imports
import json
import os
import time

# Third-party imports
import pytest

# Local imports
from joybox import config, hashing
from hashing_helpers import write_file


###########################################################
# Building a manifest
#
# What the locker actually runs. Rehashing is expensive, so most of the
# behaviour here is about doing as little as possible without letting the
# manifest drift from what is on disk.
###########################################################

@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    write_file(root, "one.bin", b"first")
    write_file(root, os.path.join("Nested", "two.bin"), b"second")
    return str(root)


@pytest.fixture
def output_file(tmp_path):
    return os.path.join(str(tmp_path), "out", "hashes.json")


###########################################################
# A single entry
###########################################################

def test_an_entry_records_the_file(tree):
    data = hashing.calculate_hash("one.bin", base_path = tree)

    assert data["filename"] == "one.bin"
    assert data["size"] == len(b"first")
    assert data["mtime"] > 0


def test_an_entry_hashes_with_xxh3(tree):
    data = hashing.calculate_hash("one.bin", base_path = tree)

    assert data["hash"] == hashing.calculate_file_xxh3(os.path.join(tree, "one.bin"))


def test_a_nested_entry_records_its_directory(tree):
    data = hashing.calculate_hash(os.path.join("Nested", "two.bin"), base_path = tree)

    assert data["dir"] == "Nested"
    assert data["filename"] == "two.bin"


def test_an_entry_carries_the_encrypted_fields_by_default(tree):
    data = hashing.calculate_hash("one.bin", base_path = tree)

    assert "filename_enc" in data
    assert data["hash_enc"] == ""
    assert data["size_enc"] == 0


def test_the_encrypted_fields_can_be_left_out(tree):
    data = hashing.calculate_hash("one.bin", base_path = tree, include_enc_fields = False)

    assert "filename_enc" not in data
    assert "hash_enc" not in data


def test_an_entry_can_be_built_from_a_full_path(tree):
    data = hashing.calculate_hash(os.path.join(tree, "one.bin"))

    assert data["filename"] == "one.bin"
    assert data["size"] == len(b"first")


def test_a_pretend_entry_carries_no_hash(tree):
    data = hashing.calculate_hash("one.bin", base_path = tree, pretend_run = True)

    assert data["filename"] == "one.bin"
    assert data["hash"] == ""
    assert data["size"] == 0


def test_a_pretend_entry_does_not_need_the_file(tmp_path):
    data = hashing.calculate_hash("absent.bin", base_path = str(tmp_path), pretend_run = True)

    assert data["filename"] == "absent.bin"


###########################################################
# A whole tree
###########################################################

def test_every_file_reaches_the_manifest(tree, output_file):
    assert hashing.hash_files(tree, output_file) is True

    contents = hashing.read_hash_file_json(output_file)
    assert sorted(contents) == ["Nested/two.bin", "one.bin"]


def test_the_manifest_directory_is_created(tree, output_file):
    hashing.hash_files(tree, output_file)

    assert os.path.isfile(output_file)


def test_a_manifest_can_be_written_as_csv(tree, tmp_path):
    output_file = os.path.join(str(tmp_path), "hashes.csv")

    hashing.hash_files(tree, output_file, hash_format = config.HashFormatType.CSV)

    assert sorted(hashing.read_hash_file_csv(output_file)) == ["Nested/two.bin", "one.bin"]


def test_a_pretend_run_writes_no_manifest(tree, output_file):
    assert hashing.hash_files(tree, output_file, pretend_run = True) is True
    assert not os.path.exists(output_file)


def test_an_empty_tree_writes_no_manifest(tmp_path, output_file):
    empty = tmp_path / "empty"
    empty.mkdir()

    assert hashing.hash_files(str(empty), output_file) is True
    assert not os.path.exists(output_file)


def test_a_file_list_needs_a_base_path(tree, output_file):
    assert hashing.hash_files(["one.bin"], output_file) is False


def test_a_file_list_hashes_only_what_it_names(tree, output_file):
    hashing.hash_files(["one.bin"], output_file, base_path = tree)

    assert list(hashing.read_hash_file_json(output_file)) == ["one.bin"]


###########################################################
# Not redoing work
###########################################################

def test_an_unchanged_file_keeps_its_recorded_hash(tree, output_file):
    hashing.hash_files(tree, output_file)
    before = hashing.read_hash_file_json(output_file)

    hashing.hash_files(tree, output_file)

    assert hashing.read_hash_file_json(output_file) == before


def test_a_changed_file_is_rehashed(tree, output_file):
    hashing.hash_files(tree, output_file)
    before = hashing.read_hash_file_json(output_file)["one.bin"]["hash"]

    write_file(tree, "one.bin", b"changed entirely")
    hashing.hash_files(tree, output_file)

    assert hashing.read_hash_file_json(output_file)["one.bin"]["hash"] != before


def test_a_new_file_joins_an_existing_manifest(tree, output_file):
    hashing.hash_files(tree, output_file)

    write_file(tree, "three.bin", b"third")
    hashing.hash_files(tree, output_file)

    assert "three.bin" in hashing.read_hash_file_json(output_file)


def test_a_deleted_file_is_left_in_the_manifest(tree, output_file):
    # Hashing only adds; clean_missing_hash_entries is what removes
    hashing.hash_files(tree, output_file)
    os.remove(os.path.join(tree, "one.bin"))

    hashing.hash_files(tree, output_file)

    assert "one.bin" in hashing.read_hash_file_json(output_file)


def test_the_manifest_does_not_hash_itself(tree):
    # Writing the manifest changes it, so an entry for it could never settle
    output_file = os.path.join(tree, "hashes.json")
    hashing.hash_files(tree, output_file)

    hashing.hash_files(tree, output_file)

    assert "hashes.json" not in hashing.read_hash_file_json(output_file)


###########################################################
# Preserving what a rehash cannot recover
###########################################################

def test_a_rehash_keeps_the_recorded_encrypted_hash(tree, output_file):
    hashing.hash_files(tree, output_file)
    contents = hashing.read_hash_file_json(output_file)
    contents["one.bin"]["hash_enc"] = "recorded"
    contents["one.bin"]["size_enc"] = 99
    hashing.write_hash_file_json(output_file, contents)

    write_file(tree, "one.bin", b"changed entirely")
    hashing.hash_files(tree, output_file)

    updated = hashing.read_hash_file_json(output_file)["one.bin"]
    assert updated["hash_enc"] == "recorded"
    assert updated["size_enc"] == 99


def test_an_unchanged_file_keeps_the_earlier_of_two_times(tree, output_file):
    # A file touched but not changed keeps the time it was first seen, so the
    # manifest records when the contents appeared rather than when they were
    # last stat'd
    hashing.hash_files(tree, output_file)
    contents = hashing.read_hash_file_json(output_file)
    contents["one.bin"]["mtime"] = 1000
    hashing.write_hash_file_json(output_file, contents)

    os.utime(os.path.join(tree, "one.bin"), (2000, 2000))
    hashing.hash_files(tree, output_file)

    assert hashing.read_hash_file_json(output_file)["one.bin"]["mtime"] == 1000


def test_a_changed_file_takes_the_new_time(tree, output_file):
    hashing.hash_files(tree, output_file)
    contents = hashing.read_hash_file_json(output_file)
    contents["one.bin"]["mtime"] = 1000
    hashing.write_hash_file_json(output_file, contents)

    write_file(tree, "one.bin", b"changed entirely")
    os.utime(os.path.join(tree, "one.bin"), (2000, 2000))
    hashing.hash_files(tree, output_file)

    assert hashing.read_hash_file_json(output_file)["one.bin"]["mtime"] == 2000


###########################################################
# Offsets
#
# Lets a subtree be hashed into a manifest that describes the whole locker.
###########################################################

def test_an_offset_prefixes_every_key(tree, output_file):
    hashing.hash_files(tree, output_file, offset = "Games")

    assert sorted(hashing.read_hash_file_json(output_file)) == [
        "Games/Nested/two.bin", "Games/one.bin"]


def test_an_offset_reaches_the_recorded_directory(tree, output_file):
    hashing.hash_files(tree, output_file, offset = "Games")

    contents = hashing.read_hash_file_json(output_file)
    assert contents["Games/Nested/two.bin"]["dir"] == "Games/Nested"


def test_an_offset_folds_away_the_dot_for_a_top_level_file(tree, output_file):
    hashing.hash_files(tree, output_file, offset = "Games")

    assert hashing.read_hash_file_json(output_file)["Games/one.bin"]["dir"] == "Games"


def test_an_offset_manifest_is_stable_across_runs(tree, output_file):
    hashing.hash_files(tree, output_file, offset = "Games")
    before = hashing.read_hash_file_json(output_file)

    hashing.hash_files(tree, output_file, offset = "Games")

    assert hashing.read_hash_file_json(output_file) == before


def test_an_offset_run_skips_what_it_already_hashed(tree, output_file, monkeypatch):
    # The manifest key carries the offset but the file on disk does not, so
    # checking the key against the disk would miss every time and rehash the
    # whole locker on every run
    hashing.hash_files(tree, output_file, offset = "Games")

    hashed = []
    real = hashing.calculate_file_xxh3
    monkeypatch.setattr(hashing, "calculate_file_xxh3",
        lambda *args, **kwargs: (hashed.append(1), real(*args, **kwargs))[1])

    hashing.hash_files(tree, output_file, offset = "Games")

    assert hashed == []


def test_an_offset_run_still_rehashes_a_changed_file(tree, output_file):
    hashing.hash_files(tree, output_file, offset = "Games")
    before = hashing.read_hash_file_json(output_file)["Games/one.bin"]["hash"]

    write_file(tree, "one.bin", b"changed entirely")
    hashing.hash_files(tree, output_file, offset = "Games")

    assert hashing.read_hash_file_json(output_file)["Games/one.bin"]["hash"] != before
