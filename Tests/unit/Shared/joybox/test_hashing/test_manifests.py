# Imports
import json
import os

# Third-party imports
import pytest

# Local imports
from joybox import cryption, hashing
from hashing_helpers import entry, manifest


###########################################################
# Hash manifests
#
# The record of what the locker holds. Entries are keyed by dir/filename, and
# the json form carries the encrypted-name fields the locker sync needs.
###########################################################

@pytest.fixture
def json_file(tmp_path):
    return os.path.join(str(tmp_path), "hashes.json")


@pytest.fixture
def csv_file(tmp_path):
    return os.path.join(str(tmp_path), "hashes.csv")


def write_raw_json(path, payload):
    with open(path, "w") as handle:
        json.dump(payload, handle)
    return path


###########################################################
# The json form
###########################################################

def test_a_json_manifest_round_trips(json_file):
    contents = manifest(entry("Games/A", "one.zip", "aaa", 10, 111))

    hashing.write_hash_file_json(json_file, contents)

    assert hashing.read_hash_file_json(json_file) == contents


def test_an_entry_is_keyed_by_its_directory_and_filename(json_file):
    write_raw_json(json_file, [{"dir": "Games/A", "filename": "one.zip", "hash": "aaa", "size": 1, "mtime": 2}])

    contents = hashing.read_hash_file_json(json_file)

    assert list(contents.keys()) == ["Games/A/one.zip"]


def test_an_entry_with_no_directory_is_keyed_by_filename_alone(json_file):
    write_raw_json(json_file, [{"dir": "", "filename": "one.zip", "hash": "aaa", "size": 1, "mtime": 2}])

    assert list(hashing.read_hash_file_json(json_file).keys()) == ["one.zip"]


def test_a_missing_encrypted_filename_is_derived(json_file):
    # Manifests written before encryption existed carry no such field
    write_raw_json(json_file, [{"dir": "Games", "filename": "one.zip", "hash": "aaa", "size": 1, "mtime": 2}])

    contents = hashing.read_hash_file_json(json_file)

    assert contents["Games/one.zip"]["filename_enc"] == cryption.generate_encrypted_filename("one.zip")


def test_a_present_encrypted_filename_is_left_alone(json_file):
    write_raw_json(json_file, [{
        "dir": "Games", "filename": "one.zip", "hash": "aaa", "size": 1, "mtime": 2,
        "filename_enc": "kept.enc"}])

    contents = hashing.read_hash_file_json(json_file)

    assert contents["Games/one.zip"]["filename_enc"] == "kept.enc"


def test_missing_encrypted_hash_and_size_default_to_empty(json_file):
    write_raw_json(json_file, [{"dir": "Games", "filename": "one.zip", "hash": "aaa", "size": 1, "mtime": 2}])

    data = hashing.read_hash_file_json(json_file)["Games/one.zip"]

    assert data["hash_enc"] == ""
    assert data["size_enc"] == 0


def test_a_manifest_that_is_not_a_list_reads_as_empty(json_file):
    write_raw_json(json_file, {"dir": "Games"})

    assert hashing.read_hash_file_json(json_file) == {}


def test_a_missing_manifest_reads_as_empty(tmp_path):
    assert hashing.read_hash_file_json(os.path.join(str(tmp_path), "absent.json")) == {}


def test_entries_are_written_in_key_order(json_file):
    contents = manifest(
        entry("Games", "zebra.zip"),
        entry("Games", "apple.zip"),
        entry("Games", "mango.zip"))

    hashing.write_hash_file_json(json_file, contents)

    with open(json_file, "r") as handle:
        written = json.load(handle)
    assert [item["filename"] for item in written] == ["apple.zip", "mango.zip", "zebra.zip"]


def test_a_pretend_write_leaves_no_manifest(json_file):
    hashing.write_hash_file_json(json_file, manifest(entry("Games", "one.zip")), pretend_run = True)

    assert not os.path.exists(json_file)


###########################################################
# The csv form
###########################################################

def test_a_csv_manifest_round_trips(csv_file):
    contents = {"Games/one.zip": {
        "dir": "Games", "filename": "one.zip", "hash": "aaa", "size": 10, "mtime": 111}}

    hashing.write_hash_file_csv(csv_file, contents)

    assert hashing.read_hash_file_csv(csv_file) == contents


def test_csv_sizes_and_times_come_back_as_numbers(csv_file):
    # Everything in a csv is text; a string size would break the mtime
    # comparison that decides whether a file needs rehashing
    contents = {"Games/one.zip": {
        "dir": "Games", "filename": "one.zip", "hash": "aaa", "size": 10, "mtime": 111}}
    hashing.write_hash_file_csv(csv_file, contents)

    data = hashing.read_hash_file_csv(csv_file)["Games/one.zip"]

    assert isinstance(data["size"], int)
    assert isinstance(data["mtime"], int)


def test_a_missing_csv_manifest_reads_as_empty(tmp_path):
    assert hashing.read_hash_file_csv(os.path.join(str(tmp_path), "absent.csv")) == {}


def test_a_csv_manifest_carries_a_header(csv_file):
    hashing.write_hash_file_csv(csv_file, {"Games/one.zip": {
        "dir": "Games", "filename": "one.zip", "hash": "aaa", "size": 1, "mtime": 2}})

    with open(csv_file, "r") as handle:
        assert handle.readline().strip() == "dir,filename,hash,size,mtime"


def test_a_csv_manifest_creates_its_parent_directory(tmp_path):
    path = os.path.join(str(tmp_path), "nested", "hashes.csv")

    assert hashing.write_hash_file_csv(path, {}) is True
    assert os.path.isfile(path)


def test_a_pretend_csv_write_leaves_no_manifest(csv_file):
    assert hashing.write_hash_file_csv(csv_file, {}, pretend_run = True) is True
    assert not os.path.exists(csv_file)


def test_csv_rows_are_written_in_key_order(csv_file):
    contents = {}
    for name in ["zebra.zip", "apple.zip", "mango.zip"]:
        contents["Games/" + name] = {
            "dir": "Games", "filename": name, "hash": "a", "size": 1, "mtime": 2}

    hashing.write_hash_file_csv(csv_file, contents)

    with open(csv_file, "r") as handle:
        rows = handle.read().splitlines()[1:]
    assert [row.split(",")[1] for row in rows] == ["apple.zip", "mango.zip", "zebra.zip"]


###########################################################
# Sorting an existing manifest
###########################################################

def test_sorting_a_manifest_keeps_every_entry(json_file):
    contents = manifest(
        entry("Games", "zebra.zip"),
        entry("Games", "apple.zip"))
    hashing.write_hash_file_json(json_file, contents)

    assert hashing.sort_hash_file(json_file) is True
    assert hashing.read_hash_file_json(json_file) == contents


def test_sorting_orders_a_manifest_written_out_of_order(json_file):
    write_raw_json(json_file, [
        {"dir": "Games", "filename": "zebra.zip", "hash": "a", "size": 1, "mtime": 2},
        {"dir": "Games", "filename": "apple.zip", "hash": "a", "size": 1, "mtime": 2}])

    hashing.sort_hash_file(json_file)

    with open(json_file, "r") as handle:
        written = json.load(handle)
    assert [item["filename"] for item in written] == ["apple.zip", "zebra.zip"]
