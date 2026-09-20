# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import hashing
from hashing_helpers import write_file


###########################################################
# Manifest entries
#
# Entries arrive from json, from csv and from older manifests with fewer
# fields. Normalizing them is what lets the rest of the module assume the
# numeric fields really are numbers.
###########################################################

STRING_FIELDS = ["dir", "filename", "filename_enc", "hash", "hash_enc"]
NUMBER_FIELDS = ["size", "size_enc", "mtime"]


###########################################################
# Normalizing
###########################################################

def test_normalizing_fills_in_every_field():
    normalized = hashing.normalize_hash_entry({})

    for field in STRING_FIELDS:
        assert normalized[field] == ""
    for field in NUMBER_FIELDS:
        assert normalized[field] == 0


def test_normalizing_keeps_the_values_that_are_present():
    normalized = hashing.normalize_hash_entry({"dir": "Games", "filename": "one.zip", "size": 10})

    assert normalized["dir"] == "Games"
    assert normalized["filename"] == "one.zip"
    assert normalized["size"] == 10


@pytest.mark.parametrize("field", NUMBER_FIELDS)
def test_a_numeric_field_read_from_csv_becomes_a_number(field):
    normalized = hashing.normalize_hash_entry({field: "42"})

    assert normalized[field] == 42
    assert isinstance(normalized[field], int)


@pytest.mark.parametrize("field", NUMBER_FIELDS)
def test_an_unparseable_number_falls_back_to_zero(field):
    normalized = hashing.normalize_hash_entry({field: "not a number"})

    assert normalized[field] == 0


@pytest.mark.parametrize("field", NUMBER_FIELDS)
def test_an_empty_number_falls_back_to_zero(field):
    assert hashing.normalize_hash_entry({field: ""})[field] == 0


def test_normalizing_does_not_touch_the_entry_it_was_given():
    original = {"dir": "Games"}

    hashing.normalize_hash_entry(original)

    assert original == {"dir": "Games"}


def test_normalizing_is_idempotent():
    once = hashing.normalize_hash_entry({"size": "42"})

    assert hashing.normalize_hash_entry(once) == once


def test_a_whole_manifest_can_be_normalized():
    contents = {"a": {"size": "1"}, "b": {"mtime": "2"}}

    normalized = hashing.normalize_hash_contents(contents)

    assert normalized["a"]["size"] == 1
    assert normalized["b"]["mtime"] == 2


def test_normalizing_a_manifest_keeps_its_keys():
    contents = {"Games/one.zip": {}, "Games/two.zip": {}}

    assert sorted(hashing.normalize_hash_contents(contents)) == ["Games/one.zip", "Games/two.zip"]


def test_an_empty_manifest_normalizes_to_an_empty_manifest():
    assert hashing.normalize_hash_contents({}) == {}


###########################################################
# Converting to the full form
###########################################################

def test_converting_adds_only_the_encrypted_fields():
    full = hashing.convert_to_full_hash_entry({"dir": "Games", "filename": "one.zip"})

    assert full["filename_enc"] == ""
    assert full["hash_enc"] == ""
    assert full["size_enc"] == 0
    assert full["dir"] == "Games"


def test_converting_leaves_existing_encrypted_fields_alone():
    full = hashing.convert_to_full_hash_entry({"filename_enc": "kept.enc", "size_enc": 99})

    assert full["filename_enc"] == "kept.enc"
    assert full["size_enc"] == 99


def test_converting_does_not_touch_the_entry_it_was_given():
    original = {"dir": "Games"}

    hashing.convert_to_full_hash_entry(original)

    assert "filename_enc" not in original


def test_converting_does_not_coerce_numbers():
    # Unlike normalizing, this only fills in the encrypted fields
    assert hashing.convert_to_full_hash_entry({"size": "10"})["size"] == "10"


###########################################################
# Deciding what needs rehashing
#
# Rehashing a whole locker is expensive, so this decides per file. Saying no
# when a file really did change would leave a stale hash in the manifest.
###########################################################

@pytest.fixture
def hashed(tmp_path):
    path = write_file(tmp_path, "one.zip", b"payload")
    contents = {"one.zip": {
        "dir": "",
        "filename": "one.zip",
        "hash": "aaa",
        "size": os.path.getsize(path),
        "mtime": int(os.path.getmtime(path)),
    }}
    return str(tmp_path), contents


def test_an_unchanged_file_does_not_need_rehashing(hashed):
    base, contents = hashed

    assert hashing.does_file_need_to_be_hashed("one.zip", base, contents) is False


def test_a_file_not_in_the_manifest_needs_hashing(hashed):
    base, contents = hashed

    assert hashing.does_file_need_to_be_hashed("two.zip", base, contents) is True


def test_a_resized_file_needs_rehashing(hashed):
    base, contents = hashed
    contents["one.zip"]["size"] = 999

    assert hashing.does_file_need_to_be_hashed("one.zip", base, contents) is True


def test_a_retouched_file_needs_rehashing(hashed):
    base, contents = hashed
    contents["one.zip"]["mtime"] = 1

    assert hashing.does_file_need_to_be_hashed("one.zip", base, contents) is True


def test_a_file_that_has_gone_missing_needs_rehashing(hashed):
    base, contents = hashed
    os.remove(os.path.join(base, "one.zip"))

    assert hashing.does_file_need_to_be_hashed("one.zip", base, contents) is True


def test_a_size_recorded_as_text_still_compares(hashed):
    # csv manifests carry every field as text
    base, contents = hashed
    contents["one.zip"]["size"] = str(contents["one.zip"]["size"])

    assert hashing.does_file_need_to_be_hashed("one.zip", base, contents) is False


def test_an_unparseable_size_forces_a_rehash(hashed):
    base, contents = hashed
    contents["one.zip"]["size"] = "corrupt"

    assert hashing.does_file_need_to_be_hashed("one.zip", base, contents) is True


def test_an_entry_missing_its_size_forces_a_rehash(hashed):
    base, contents = hashed
    del contents["one.zip"]["size"]

    assert hashing.does_file_need_to_be_hashed("one.zip", base, contents) is True


def test_an_empty_manifest_means_everything_needs_hashing(tmp_path):
    assert hashing.does_file_need_to_be_hashed("one.zip", str(tmp_path), {}) is True


def test_a_key_that_differs_from_the_path_on_disk_is_still_checked(hashed):
    # An offset manifest keys entries by a path that does not exist on disk
    base, contents = hashed
    contents["Games/one.zip"] = contents.pop("one.zip")

    assert hashing.does_file_need_to_be_hashed(
        "Games/one.zip", base, contents, file_path = "one.zip") is False


def test_a_key_that_differs_from_the_path_still_notices_a_change(hashed):
    base, contents = hashed
    contents["Games/one.zip"] = contents.pop("one.zip")
    contents["Games/one.zip"]["size"] = 999

    assert hashing.does_file_need_to_be_hashed(
        "Games/one.zip", base, contents, file_path = "one.zip") is True
