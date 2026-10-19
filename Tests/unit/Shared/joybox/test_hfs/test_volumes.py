# Imports
import os
import struct

# Third-party imports
import pytest

# Local imports
from joybox import hfs
from hfs_helpers import (
    CLASSIC_VOLUME_SIZE, HFS_START_BLOCK, NEW_YEAR_2005, APPLICATION_INFO, HFSPlusBuilder,
    make_classic_volume, make_apm_image, make_signed_image, make_wrapped_image, read_appledouble_entries)


###########################################################
# Finding the volume
###########################################################

@pytest.fixture
def write_image(tmp_path):
    def write(contents, name = "Game.iso"):
        target = tmp_path / name
        target.write_bytes(contents)
        return str(target)
    return write


def test_a_partition_map_points_at_the_hfs_volume(write_image):
    image = write_image(make_apm_image(make_classic_volume()))

    assert hfs.find_hfs_volume(image) == (HFS_START_BLOCK * 512, CLASSIC_VOLUME_SIZE, b"BD")


def test_a_partition_map_without_a_block_size_counts_in_512_bytes(write_image):
    image = write_image(make_apm_image(make_classic_volume(), block_size = 0))

    assert hfs.find_hfs_volume(image) == (HFS_START_BLOCK * 512, CLASSIC_VOLUME_SIZE, b"BD")


def test_a_partition_map_points_at_an_hfsplus_volume(write_image):
    volume = HFSPlusBuilder().build()
    image = write_image(make_apm_image(volume))

    assert hfs.find_hfs_volume(image) == (HFS_START_BLOCK * 512, len(volume), b"H+")


def test_a_bare_volume_starts_the_image(write_image):
    image = write_image(make_classic_volume())

    assert hfs.find_hfs_volume(image) == (0, CLASSIC_VOLUME_SIZE, b"BD")


@pytest.mark.parametrize("signature", [b"H+", b"HX"])
def test_a_bare_hfsplus_volume_is_found_by_its_signature(write_image, signature):
    image = write_image(make_signed_image(signature))

    assert hfs.find_hfs_volume(image) == (0, 4096, signature)


def test_a_wrapper_volume_gives_the_hfsplus_volume_inside_it(write_image):
    volume = HFSPlusBuilder().build()
    image = write_image(make_wrapped_image(volume, embed_start = 8))

    assert hfs.find_hfs_volume(image) == (8 * 512, len(volume), b"H+")


@pytest.mark.parametrize("contents", [
    make_apm_image(make_classic_volume(), partition_type = b"Apple_Free"),
    b"ER" + b"\0" * 2000,
    make_signed_image(b"CD"),
    b"\0" * 1100,
    b"abc",
])
def test_an_image_without_an_hfs_volume_has_none(write_image, contents):
    assert hfs.find_hfs_volume(write_image(contents)) is None


###########################################################
# Names and metadata
###########################################################

@pytest.mark.parametrize("hfs_name, local_name", [
    ("Read Me", "Read Me"),
    ("Either/Or", "Either:Or"),
    ("Café", "Café"),
    ("..", None),
    ("", None),
    ("\0\0\0\0HFS+ Private Data", None),
])
def test_mac_names_become_local_names(hfs_name, local_name):
    assert hfs.get_local_filename(hfs_name) == local_name


def test_an_unset_date_is_unknown_in_appledouble():
    assert hfs.convert_hfs_date_to_appledouble(0) == hfs.appledouble_unknown_date
    assert hfs.convert_hfs_date_to_appledouble(hfs.hfs_to_appledouble_seconds + 5) == 5


@pytest.mark.parametrize("finder_info, resource_fork_size, needed", [
    (b"        " + bytes(24), 0, False),
    (bytes(32), 0, False),
    (bytes(32), 1, True),
    (bytes(8) + b"\x40\x00" + bytes(22), 0, True),
    (b"TEXT    " + bytes(24), 0, True),
    (b"    ttxt" + bytes(24), 0, True),
])
def test_only_mac_metadata_needs_an_appledouble_file(finder_info, resource_fork_size, needed):
    assert hfs.does_finder_info_need_appledouble(finder_info, resource_fork_size) is needed


def test_appledouble_carries_the_finder_info_dates_and_resource_fork():
    blob = hfs.build_appledouble(APPLICATION_INFO[:8] + b"\x01\x00", (0, NEW_YEAR_2005, 0), b"resources")

    magic, version, entries = read_appledouble_entries(blob)
    assert (magic, version) == (hfs.appledouble_magic, hfs.appledouble_version)
    assert entries[hfs.appledouble_entry_finder_info] == b"APPLPJ03\x01\x00" + bytes(22)
    assert entries[hfs.appledouble_entry_resource_fork] == b"resources"
    _, modified, backed_up, _ = struct.unpack(">iiii", entries[hfs.appledouble_entry_file_dates])
    assert modified == NEW_YEAR_2005 - hfs.hfs_to_appledouble_seconds
    assert backed_up == hfs.appledouble_unknown_date


###########################################################
# Extracting either kind
###########################################################

@pytest.fixture(params = ["HFS", "HFS+"])
def volume_image(request, write_image):
    if request.param == "HFS":
        return write_image(make_classic_volume())
    builder = HFSPlusBuilder()
    builder.add_file(2, 16, "Read Me", data = b"plain text")
    return write_image(builder.build())


def test_extracting_deletes_the_image_when_asked(volume_image, tmp_path):
    assert hfs.extract_hfs(volume_image, str(tmp_path / "Game"), delete_original = True, verbose = True) is True
    assert not os.path.exists(volume_image)


def test_pretending_to_extract_writes_nothing(volume_image, tmp_path):
    output = tmp_path / "Game"

    assert hfs.extract_hfs(volume_image, str(output), pretend_run = True) is True
    assert not output.exists()


def test_a_failed_extraction_keeps_the_image(monkeypatch, volume_image, tmp_path):
    monkeypatch.setattr(hfs.fileops, "make_directory", lambda **kwargs: False)

    assert hfs.extract_hfs(volume_image, str(tmp_path / "Game"), delete_original = True) is False
    assert os.path.exists(volume_image)


def test_a_missing_image_reports_failure(tmp_path):
    assert hfs.extract_hfs(str(tmp_path / "absent.iso"), str(tmp_path / "Game")) is False


def test_an_image_without_a_volume_reports_failure(write_image, tmp_path, caplog):
    assert hfs.extract_hfs(write_image(make_signed_image(b"CD")), str(tmp_path / "Game")) is False
    assert "No HFS volume" in caplog.text
