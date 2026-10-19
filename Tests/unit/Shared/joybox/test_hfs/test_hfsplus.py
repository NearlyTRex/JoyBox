# Imports
import os
import stat

# Third-party imports
import pytest

# Local imports
from joybox import hfs
from hfs_helpers import (
    NEW_YEAR_2005, APPLICATION_INFO, HARD_LINK_INFO, NODE_SIZE, HFSPlusBuilder,
    build_btree, catalog_record, make_apm_image, read_appledouble_entries)


###########################################################
# HFS+
#
# The catalog B-tree names every file and folder; their forks are runs of
# allocation blocks, the first eight in the catalog and the rest in the
# extents overflow B-tree. Each volume here is built block by block.
###########################################################

BIG_DATA = bytes(range(256)) * 40
PRIVATE_FOLDER_ID = 30


@pytest.fixture
def builder():
    return HFSPlusBuilder()


@pytest.fixture
def extract(tmp_path):
    def run(builder_or_bytes, wrap = True, **kwargs):
        volume = builder_or_bytes if isinstance(builder_or_bytes, bytes) else builder_or_bytes.build()
        target = tmp_path / "Game.iso"
        target.write_bytes(make_apm_image(volume) if wrap else volume)
        output = tmp_path / "Game"
        return hfs.extract_hfs(str(target), str(output), **kwargs), output
    return run


###########################################################
# Files and folders
###########################################################

def test_files_and_folders_are_extracted(builder, extract):
    builder.add_folder(2, 16, "Data")
    builder.add_file(16, 17, "movie.mov", data = BIG_DATA)
    builder.add_file(2, 18, "Read Me", data = b"plain text")

    success, output = extract(builder)

    assert success is True
    assert (output / "Data" / "movie.mov").read_bytes() == BIG_DATA
    assert (output / "Read Me").read_bytes() == b"plain text"


def test_names_are_normalised_and_slashes_swapped(builder, extract):
    builder.add_file(2, 16, "Café Either/Or", data = b"x")

    _, output = extract(builder)

    assert os.listdir(str(output)) == ["Café Either:Or"]


def test_a_fragmented_file_reads_its_overflow_extents(builder, extract):
    builder.add_file(2, 16, "movie.mov", data = BIG_DATA, fragments = 20)

    _, output = extract(builder)

    assert (output / "movie.mov").read_bytes() == BIG_DATA


def test_a_fragmented_catalog_reads_its_overflow_extents(builder, extract):
    for index in range(40):
        builder.add_file(2, 100 + index, "File %02d" % index, data = b"%d" % index)

    success, output = extract(builder.build(catalog_fragments = 12))

    assert success is True
    assert len(os.listdir(str(output))) == 40


def test_a_large_file_is_written_in_chunks(monkeypatch, builder, extract):
    monkeypatch.setattr(hfs, "hfsplus_chunk_size", 1000)
    builder.add_file(2, 16, "movie.mov", data = BIG_DATA, fragments = 3)

    _, output = extract(builder)

    assert (output / "movie.mov").read_bytes() == BIG_DATA


def test_an_empty_file_is_created(builder, extract):
    builder.add_file(2, 16, "Empty")

    _, output = extract(builder)

    assert (output / "Empty").read_bytes() == b""


def test_a_case_sensitive_volume_reads_the_same(extract):
    builder = HFSPlusBuilder(signature = b"HX")
    builder.add_file(2, 16, "Read Me", data = b"plain text")

    _, output = extract(builder, wrap = False)

    assert (output / "Read Me").read_bytes() == b"plain text"


###########################################################
# Mac metadata
###########################################################

def test_finder_info_and_resource_fork_go_to_appledouble(builder, extract):
    builder.add_file(2, 16, "Start", data = b"code", rsrc = b"resources", finder_info = APPLICATION_INFO)
    builder.add_file(2, 17, "Read Me", data = b"plain text")

    _, output = extract(builder)

    _, _, entries = read_appledouble_entries((output / "._Start").read_bytes())
    assert entries[hfs.appledouble_entry_finder_info] == APPLICATION_INFO
    assert entries[hfs.appledouble_entry_resource_fork] == b"resources"
    assert not (output / "._Read Me").exists()


def test_the_modified_date_is_kept(builder, extract):
    builder.add_file(2, 16, "Read Me", data = b"x", dates = (0, NEW_YEAR_2005, 0))

    _, output = extract(builder)

    assert os.path.getmtime(str(output / "Read Me")) == NEW_YEAR_2005 - hfs.hfs_to_unix_seconds


def test_the_executable_bit_is_kept(builder, extract):
    builder.add_file(2, 16, "installer", data = b"\xca\xfe", mode = 0o100755)
    builder.add_file(2, 17, "readme.txt", data = b"x", mode = 0o100644)

    _, output = extract(builder)

    assert os.stat(str(output / "installer")).st_mode & stat.S_IXUSR
    assert not os.stat(str(output / "readme.txt")).st_mode & stat.S_IXUSR


def test_a_symlink_is_made_a_symlink(builder, extract):
    builder.add_file(2, 16, "Read Me", data = b"x")
    builder.add_file(2, 17, "Shortcut", data = b"Read Me", mode = 0o120755)

    _, output = extract(builder)

    assert os.readlink(str(output / "Shortcut")) == "Read Me"


###########################################################
# Filesystem internals
###########################################################

def add_private_folder(builder):
    builder.add_folder(2, PRIVATE_FOLDER_ID, hfs.hfsplus_private_data_name)
    builder.add_file(PRIVATE_FOLDER_ID, 31, "iNode42", data = b"shared contents", dates = (0, NEW_YEAR_2005, 0))


def test_a_hard_link_takes_its_target_contents(builder, extract):
    add_private_folder(builder)
    builder.add_file(2, 16, "Linked", finder_info = HARD_LINK_INFO, special = 42)

    _, output = extract(builder)

    assert (output / "Linked").read_bytes() == b"shared contents"
    assert os.path.getmtime(str(output / "Linked")) == NEW_YEAR_2005 - hfs.hfs_to_unix_seconds


def test_a_hard_link_without_a_target_is_skipped(builder, extract, caplog):
    add_private_folder(builder)
    builder.add_file(2, 16, "Linked", finder_info = HARD_LINK_INFO, special = 7)
    builder.add_file(2, 17, "Kept", data = b"x")

    success, output = extract(builder)

    assert success is True
    assert os.listdir(str(output)) == ["Kept"]
    assert "hard link" in caplog.text


def test_volume_internals_at_the_root_are_skipped(builder, extract):
    add_private_folder(builder)
    builder.add_file(2, 16, ".journal", data = b"journal")
    builder.add_file(2, 17, ".journal_info_block", data = b"info")
    builder.add_folder(2, 18, "Data")
    builder.add_file(18, 19, ".journal", data = b"kept")

    _, output = extract(builder)

    assert sorted(os.listdir(str(output))) == ["Data"]
    assert (output / "Data" / ".journal").read_bytes() == b"kept"


def test_a_compressed_file_is_skipped(builder, extract, caplog):
    builder.add_file(2, 16, "Packed", data = b"zlib", owner_flags = hfs.hfsplus_compressed_flag)
    builder.add_file(2, 17, "Kept", data = b"x")

    _, output = extract(builder)

    assert os.listdir(str(output)) == ["Kept"]
    assert "compressed" in caplog.text


def test_an_unusable_name_is_skipped(builder, extract, caplog):
    builder.add_file(2, 16, "bad\0name", data = b"x")
    builder.add_file(2, 17, "Kept", data = b"x")

    _, output = extract(builder)

    assert os.listdir(str(output)) == ["Kept"]
    assert "unusable name" in caplog.text


###########################################################
# Damaged volumes
###########################################################

def test_a_fork_missing_its_overflow_extents_reports_failure(builder, extract, caplog):
    builder.add_file(2, 16, "movie.mov", data = BIG_DATA, fragments = 20, keep_overflow = False)

    assert extract(builder)[0] is False
    assert "missing" in caplog.text


def test_a_fork_larger_than_its_extents_reports_failure(builder, extract, caplog):
    builder.add_file(2, 16, "movie.mov", data = b"short", size = 100000)

    assert extract(builder)[0] is False
    assert "Unable to read the HFS+ volume" in caplog.text


def test_a_fork_past_the_end_of_the_image_reports_failure(tmp_path):
    target = tmp_path / "Game.iso"
    target.write_bytes(bytes(1024))
    volume = {"image_file": str(target), "offset": 0, "block_size": 512, "overflow": {}}
    fork = {"size": 512, "blocks": 1, "extents": [(10, 1)]}

    with pytest.raises(ValueError, match = "past the end"):
        hfs.read_hfsplus_fork(volume, 16, hfs.hfsplus_data_fork, fork)


@pytest.mark.parametrize("catalog_tree, message", [
    (b"", "too short"),
    (bytes(NODE_SIZE), "no node size"),
    (build_btree([catalog_record(2, "File", bytes(2))], leaf_kind = 0), "not a leaf"),
    (build_btree([catalog_record(2, "File", bytes(2))])[:NODE_SIZE], "past the end of its file"),
])
def test_a_damaged_catalog_reports_failure(builder, extract, caplog, catalog_tree, message):
    assert extract(builder.build(catalog_tree = catalog_tree))[0] is False
    assert message in caplog.text


def test_a_leaf_chain_that_loops_is_read_once(builder):
    records = sorted(builder.catalog_records)

    assert list(hfs.iterate_btree_leaf_records(build_btree(records, loop_last_leaf = True))) == records


def test_a_volume_header_past_the_end_of_the_image_reports_failure(extract, caplog):
    volume = bytearray(1200)
    volume[1024:1026] = b"H+"

    assert extract(bytes(volume), wrap = False)[0] is False
    assert "header is past the end" in caplog.text


###########################################################
# Failed writes
###########################################################

@pytest.mark.parametrize("failing_name", ["Data", "Data/movie.mov", "Empty", "._Start", "Shortcut"])
def test_a_write_that_fails_stops_the_extraction(monkeypatch, builder, extract, tmp_path, failing_name):
    builder.add_folder(2, 16, "Data")
    builder.add_file(16, 17, "movie.mov", data = BIG_DATA)
    builder.add_file(2, 18, "Empty")
    builder.add_file(2, 19, "Start", data = b"code", rsrc = b"resources", finder_info = APPLICATION_INFO)
    builder.add_file(2, 20, "Shortcut", data = b"Start", mode = 0o120755)
    failing = str(tmp_path / "Game" / failing_name)
    make_directory, touch_file, create_symlink = hfs.fileops.make_directory, hfs.fileops.touch_file, hfs.fileops.create_symlink
    monkeypatch.setattr(hfs.fileops, "make_directory", lambda src, **kwargs: src != failing and make_directory(src, **kwargs))
    monkeypatch.setattr(hfs.fileops, "touch_file", lambda src, **kwargs: src != failing and touch_file(src, **kwargs))
    monkeypatch.setattr(hfs.fileops, "create_symlink", lambda src, dest, **kwargs: dest != failing and create_symlink(src, dest, **kwargs))

    assert extract(builder)[0] is False
