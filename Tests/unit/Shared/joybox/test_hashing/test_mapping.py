# Imports
import json
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, hashing
from hashing_helpers import entry, manifest, write_file


###########################################################
# Hashing a tree, and keeping the manifest true
###########################################################

def write_manifest(path, entries):
    with open(path, "w") as handle:
        json.dump(entries, handle)
    return path


###########################################################
# Building a hash map
###########################################################

@pytest.fixture
def tree(tmp_path):
    write_file(tmp_path, "one.bin", b"first")
    write_file(tmp_path, os.path.join("Nested", "two.bin"), b"second")
    return str(tmp_path)


def test_every_file_in_the_tree_is_mapped(tree):
    hash_map = hashing.build_hash_map(tree)

    assert sorted(hash_map) == sorted(["one.bin", os.path.join("Nested", "two.bin")])


def test_an_entry_records_where_the_file_sits(tree):
    hash_map = hashing.build_hash_map(tree)

    nested = hash_map[os.path.join("Nested", "two.bin")]
    assert nested["filename"] == "two.bin"
    assert nested["dir"] == "Nested"


def test_a_file_at_the_top_records_a_dot_for_its_directory(tree):
    # What calculate_hash writes too, so it is the form already on disk in
    # every manifest. join_paths folds it away, so the key stays clean.
    assert hashing.build_hash_map(tree)["one.bin"]["dir"] == "."


def test_a_top_level_entry_keys_back_to_its_relative_path(tmp_path, tree):
    # The dot must not leak into the key, or a re-read manifest would not
    # match the map it was written from and every file would rehash
    hash_file = os.path.join(str(tmp_path), "hashes.json")
    hashing.write_hash_file_json(hash_file, hashing.build_hash_map(tree))

    assert "one.bin" in hashing.read_hash_file_json(hash_file)


def test_an_entry_records_the_size_and_time(tree):
    hash_map = hashing.build_hash_map(tree)

    assert hash_map["one.bin"]["size"] == len(b"first")
    assert hash_map["one.bin"]["mtime"] > 0


def test_the_default_hash_is_md5(tree):
    hash_map = hashing.build_hash_map(tree)

    expected = hashing.calculate_file_md5(os.path.join(tree, "one.bin"))
    assert hash_map["one.bin"]["hash"] == expected


@pytest.mark.parametrize("hash_type,function", [
    (config.HashType.MD5, hashing.calculate_file_md5),
    (config.HashType.SHA256, hashing.calculate_file_sha256),
    (config.HashType.CRC32, hashing.calculate_file_crc32),
])
def test_the_hash_type_chooses_the_digest(tree, hash_type, function):
    hash_map = hashing.build_hash_map(tree, hash_type = hash_type)

    assert hash_map["one.bin"]["hash"] == function(os.path.join(tree, "one.bin"))


def test_a_missing_tree_maps_to_nothing(tmp_path):
    assert hashing.build_hash_map(os.path.join(str(tmp_path), "absent")) == {}


def test_an_empty_tree_maps_to_nothing(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    assert hashing.build_hash_map(str(empty)) == {}


def test_an_excluded_file_is_left_out(tree):
    hash_map = hashing.build_hash_map(tree, excludes = ["one.bin"])

    assert "one.bin" not in hash_map
    assert os.path.join("Nested", "two.bin") in hash_map


def test_an_excluded_directory_takes_its_contents_with_it(tree):
    hash_map = hashing.build_hash_map(tree, excludes = ["Nested/**"])

    assert list(hash_map) == ["one.bin"]


def test_a_wildcard_exclusion_matches_by_extension(tmp_path):
    write_file(tmp_path, "keep.bin", b"keep")
    write_file(tmp_path, "drop.tmp", b"drop")

    hash_map = hashing.build_hash_map(str(tmp_path), excludes = ["*.tmp"])

    assert list(hash_map) == ["keep.bin"]


def test_an_exclusion_that_matches_nothing_leaves_the_tree_alone(tree):
    assert len(hashing.build_hash_map(tree, excludes = ["absent.bin"])) == 2


###########################################################
# Dropping entries for files that are gone
#
# A manifest that still lists a deleted file makes the locker look like it
# holds something it does not.
###########################################################

@pytest.fixture
def locker(tmp_path):
    root = tmp_path / "locker"
    root.mkdir()
    write_file(root, os.path.join("Games", "present.zip"), b"payload")
    return str(root)


def test_an_entry_for_a_missing_file_is_dropped(tmp_path, locker):
    hash_file = write_manifest(os.path.join(str(tmp_path), "hashes.json"), [
        {"dir": "Games", "filename": "present.zip", "hash": "a", "size": 7, "mtime": 1},
        {"dir": "Games", "filename": "gone.zip", "hash": "b", "size": 7, "mtime": 1}])

    assert hashing.clean_missing_hash_entries(hash_file, locker) is True

    remaining = hashing.read_hash_file_json(hash_file)
    assert list(remaining) == ["Games/present.zip"]


def test_a_manifest_with_nothing_missing_is_left_alone(tmp_path, locker):
    hash_file = write_manifest(os.path.join(str(tmp_path), "hashes.json"), [
        {"dir": "Games", "filename": "present.zip", "hash": "a", "size": 7, "mtime": 1}])
    before = os.path.getmtime(hash_file)

    assert hashing.clean_missing_hash_entries(hash_file, locker) is True
    assert os.path.getmtime(hash_file) == before


def test_a_missing_manifest_is_not_an_error(tmp_path, locker):
    absent = os.path.join(str(tmp_path), "absent.json")

    assert hashing.clean_missing_hash_entries(absent, locker) is True


def test_a_pretend_clean_leaves_the_manifest_as_it_was(tmp_path, locker):
    hash_file = write_manifest(os.path.join(str(tmp_path), "hashes.json"), [
        {"dir": "Games", "filename": "gone.zip", "hash": "b", "size": 7, "mtime": 1}])

    assert hashing.clean_missing_hash_entries(hash_file, locker, pretend_run = True) is True
    assert list(hashing.read_hash_file_json(hash_file)) == ["Games/gone.zip"]


def test_a_csv_manifest_is_cleaned_too(tmp_path, locker):
    hash_file = os.path.join(str(tmp_path), "hashes.csv")
    hashing.write_hash_file_csv(hash_file, {
        "Games/present.zip": {"dir": "Games", "filename": "present.zip", "hash": "a", "size": 7, "mtime": 1},
        "Games/gone.zip": {"dir": "Games", "filename": "gone.zip", "hash": "b", "size": 7, "mtime": 1}})

    hashing.clean_missing_hash_entries(hash_file, locker, hash_format = config.HashFormatType.CSV)

    assert list(hashing.read_hash_file_csv(hash_file)) == ["Games/present.zip"]


def test_an_entry_whose_whole_directory_is_gone_is_dropped(tmp_path, locker):
    hash_file = write_manifest(os.path.join(str(tmp_path), "hashes.json"), [
        {"dir": "Removed", "filename": "one.zip", "hash": "a", "size": 7, "mtime": 1}])

    hashing.clean_missing_hash_entries(hash_file, locker)

    assert hashing.read_hash_file_json(hash_file) == {}


###########################################################
# Grouping files for transfer
#
# Files from one directory stay together, so a group is a coherent set rather
# than an arbitrary slice.
###########################################################

def build_hash_file(tmp_path, name, entries):
    return write_manifest(os.path.join(str(tmp_path), name), entries)


def test_files_fitting_the_limit_land_in_one_group(tmp_path):
    hash_file = build_hash_file(tmp_path, "a.json", [
        {"dir": "Games", "filename": "one.zip", "hash": "a", "size": 10, "mtime": 1},
        {"dir": "Games", "filename": "two.zip", "hash": "b", "size": 10, "mtime": 1}])

    groups = hashing.get_file_groupings([hash_file], 100)

    assert list(groups) == ["Group1"]
    assert sorted(groups["Group1"]["files"]) == ["Games/one.zip", "Games/two.zip"]


def test_a_group_records_its_total_size(tmp_path):
    hash_file = build_hash_file(tmp_path, "a.json", [
        {"dir": "Games", "filename": "one.zip", "hash": "a", "size": 10, "mtime": 1},
        {"dir": "Games", "filename": "two.zip", "hash": "b", "size": 30, "mtime": 1}])

    groups = hashing.get_file_groupings([hash_file], 100)

    assert groups["Group1"]["size"] == 40


def test_exceeding_the_limit_starts_a_new_group(tmp_path):
    hash_file = build_hash_file(tmp_path, "a.json", [
        {"dir": "First", "filename": "one.zip", "hash": "a", "size": 60, "mtime": 1},
        {"dir": "Second", "filename": "two.zip", "hash": "b", "size": 60, "mtime": 1}])

    groups = hashing.get_file_groupings([hash_file], 100)

    assert sorted(groups) == ["Group1", "Group2"]


def test_a_directory_is_never_split_across_groups(tmp_path):
    # Even when it is larger than the limit on its own
    hash_file = build_hash_file(tmp_path, "a.json", [
        {"dir": "Big", "filename": "one.zip", "hash": "a", "size": 80, "mtime": 1},
        {"dir": "Big", "filename": "two.zip", "hash": "b", "size": 80, "mtime": 1}])

    groups = hashing.get_file_groupings([hash_file], 100)

    assert list(groups) == ["Group1"]
    assert len(groups["Group1"]["files"]) == 2


def test_several_manifests_are_grouped_together(tmp_path):
    first = build_hash_file(tmp_path, "a.json", [
        {"dir": "First", "filename": "one.zip", "hash": "a", "size": 10, "mtime": 1}])
    second = build_hash_file(tmp_path, "b.json", [
        {"dir": "Second", "filename": "two.zip", "hash": "b", "size": 10, "mtime": 1}])

    groups = hashing.get_file_groupings([first, second], 100)

    assert sorted(groups["Group1"]["files"]) == ["First/one.zip", "Second/two.zip"]


def test_no_manifests_still_yields_an_empty_first_group(tmp_path):
    groups = hashing.get_file_groupings([], 100)

    assert groups == {"Group1": {"size": 0, "files": []}}
