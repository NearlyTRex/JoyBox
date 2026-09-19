# Imports
import json
import os

# Third-party imports
import pytest

# Local imports
from joybox import cryption, hashing


###########################################################
# Hash sidecars
#
# The sidecar is the record of what the collection contains and what was
# uploaded, so its shape is a data format - a read that drops or renames a
# field breaks every later comparison.
###########################################################

RECORDS = [
    {"dir": "Roms/Nintendo/Nintendo 64/B Game", "filename": "B Game.z64",
     "hash": "bbbb", "size": "200", "mtime": "2"},
    {"dir": "Roms/Nintendo/Nintendo 64/A Game", "filename": "A Game.z64",
     "hash": "aaaa", "size": "100", "mtime": "1"},
]


@pytest.fixture
def sidecar(tmp_path):
    path = str(tmp_path / "hashes.json")
    with open(path, "w") as handle:
        handle.write(json.dumps(RECORDS))
    return path


def load(path):
    with open(path) as handle:
        return json.load(handle)


###########################################################
# Reading
###########################################################

def test_entries_are_keyed_by_their_full_location(sidecar):
    contents = hashing.read_hash_file_json(sidecar)

    assert "Roms/Nintendo/Nintendo 64/A Game/A Game.z64" in contents


def test_every_record_is_read(sidecar):
    assert len(hashing.read_hash_file_json(sidecar)) == len(RECORDS)


def test_the_original_fields_survive_a_read(sidecar):
    contents = hashing.read_hash_file_json(sidecar)
    entry = contents["Roms/Nintendo/Nintendo 64/A Game/A Game.z64"]

    assert entry["hash"] == "aaaa"
    assert entry["size"] == "100"
    assert entry["mtime"] == "1"


def test_encrypted_fields_are_filled_in(sidecar):
    # The locker stores files under an encrypted name, so a sidecar written
    # before encryption still has to resolve one.
    contents = hashing.read_hash_file_json(sidecar)
    entry = contents["Roms/Nintendo/Nintendo 64/A Game/A Game.z64"]

    assert entry["filename_enc"] == cryption.generate_encrypted_filename("A Game.z64")
    assert entry["hash_enc"] == ""
    assert entry["size_enc"] == 0


def test_existing_encrypted_fields_are_not_overwritten(tmp_path):
    path = str(tmp_path / "hashes.json")
    with open(path, "w") as handle:
        handle.write(json.dumps([{
            "dir": "Roms/A", "filename": "a.z64", "hash": "aaaa", "size": "1", "mtime": "1",
            "filename_enc": "already.enc", "hash_enc": "existing", "size_enc": 42,
        }]))

    entry = hashing.read_hash_file_json(path)["Roms/A/a.z64"]

    assert entry["filename_enc"] == "already.enc"
    assert entry["hash_enc"] == "existing"
    assert entry["size_enc"] == 42


def test_a_missing_sidecar_reads_as_empty(tmp_path):
    assert hashing.read_hash_file_json(str(tmp_path / "absent.json")) == {}


def test_a_malformed_sidecar_reads_as_empty(tmp_path):
    path = str(tmp_path / "hashes.json")
    with open(path, "w") as handle:
        handle.write("{not json")

    assert hashing.read_hash_file_json(path) == {}


def test_an_object_instead_of_a_list_reads_as_empty(tmp_path):
    # Only the list form is a sidecar; a bare object is something else.
    path = str(tmp_path / "hashes.json")
    with open(path, "w") as handle:
        handle.write(json.dumps({"not": "a list"}))

    assert hashing.read_hash_file_json(path) == {}


###########################################################
# Writing
###########################################################

def test_a_sidecar_round_trips(sidecar):
    contents = hashing.read_hash_file_json(sidecar)
    hashing.write_hash_file_json(sidecar, contents)

    assert hashing.read_hash_file_json(sidecar) == contents


def test_a_written_sidecar_is_a_list(sidecar):
    hashing.write_hash_file_json(sidecar, hashing.read_hash_file_json(sidecar))

    assert isinstance(load(sidecar), list)


def test_writing_preserves_every_entry(sidecar):
    contents = hashing.read_hash_file_json(sidecar)
    hashing.write_hash_file_json(sidecar, contents)

    assert len(load(sidecar)) == len(RECORDS)


def test_pretend_run_does_not_write(sidecar):
    before = load(sidecar)
    hashing.write_hash_file_json(sidecar, {}, pretend_run = True)

    assert load(sidecar) == before


###########################################################
# Sorting
###########################################################

def test_sorting_orders_entries_by_location(sidecar):
    # A stable order keeps the git diff on the metadata repo readable.
    hashing.sort_hash_file(sidecar)

    assert [entry["filename"] for entry in load(sidecar)] == ["A Game.z64", "B Game.z64"]


def test_sorting_keeps_every_entry(sidecar):
    hashing.sort_hash_file(sidecar)

    assert len(load(sidecar)) == len(RECORDS)


def test_sorting_is_idempotent(sidecar):
    hashing.sort_hash_file(sidecar)
    once = load(sidecar)
    hashing.sort_hash_file(sidecar)

    assert load(sidecar) == once


def test_sorting_does_not_lose_hashes(sidecar):
    hashing.sort_hash_file(sidecar)
    hashes = {entry["filename"]: entry["hash"] for entry in load(sidecar)}

    assert hashes == {"A Game.z64": "aaaa", "B Game.z64": "bbbb"}
