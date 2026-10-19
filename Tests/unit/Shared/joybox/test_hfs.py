# Imports
import os
import struct
import sys

# Third-party imports
import machfs
import pytest

# Local imports
from joybox import hfs


###########################################################
# HFS volumes
#
# The volumes are written with machfs itself, so each test reads back a real
# HFS layout; the Apple partition map around them is built by hand, as Toast
# lays it out on hybrid discs.
###########################################################

VOLUME_SIZE = 400 * 1024
HFS_START_BLOCK = 64

# 2005-01-01 00:00:00 in HFS time
NEW_YEAR_2005 = 1104537600 + hfs.hfs_to_unix_seconds


def make_file(data = b"", rsrc = b"", file_type = b"    ", creator = b"    ", flags = 0, mddate = 0):
    hfs_file = machfs.File()
    hfs_file.data = data
    hfs_file.rsrc = rsrc
    hfs_file.type = file_type
    hfs_file.creator = creator
    hfs_file.flags = flags
    hfs_file.crdate = hfs_file.mddate = mddate
    return hfs_file


def make_volume():
    volume = machfs.Volume()
    volume.name = "Hybrid"
    volume["Read Me"] = make_file(data = b"plain text", mddate = NEW_YEAR_2005)
    volume["Start"] = make_file(data = b"code", rsrc = b"resources", file_type = b"APPL", creator = b"PJ03")
    folder = machfs.Folder()
    folder["Either/Or"] = make_file(data = b"slashed")
    volume["Extras"] = folder
    return volume.write(VOLUME_SIZE)


def make_partition_entry(entry_count, start_block, block_count, partition_type):
    entry = b"PM" + b"\0\0" + struct.pack(">III", entry_count, start_block, block_count)
    entry += b"Partition".ljust(32, b"\0") + partition_type.ljust(32, b"\0")
    return entry.ljust(512, b"\0")


def make_apm_image(volume, partition_type = b"Apple_HFS", block_size = 512):
    image = b"ER" + struct.pack(">H", block_size)
    image = image.ljust(512, b"\0")
    image += make_partition_entry(2, 1, 2, b"Apple_partition_map")
    image += make_partition_entry(2, HFS_START_BLOCK, len(volume) // 512, partition_type)
    return image.ljust(HFS_START_BLOCK * 512, b"\0") + volume


def make_signed_image(signature, embedded_signature = b"\0\0"):
    image = bytearray(4096)
    image[1024:1026] = signature
    image[1024 + 0x7C:1024 + 0x7E] = embedded_signature
    return bytes(image)


@pytest.fixture
def write_image(tmp_path):
    def write(contents, name = "Game.iso"):
        target = tmp_path / name
        target.write_bytes(contents)
        return str(target)
    return write


###########################################################
# Finding the volume
###########################################################

def test_a_partition_map_points_at_the_hfs_volume(write_image):
    image = write_image(make_apm_image(make_volume()))

    assert hfs.find_hfs_volume(image) == (HFS_START_BLOCK * 512, VOLUME_SIZE, b"BD")


def test_a_partition_map_without_a_block_size_counts_in_512_bytes(write_image):
    image = write_image(make_apm_image(make_volume(), block_size = 0))

    assert hfs.find_hfs_volume(image) == (HFS_START_BLOCK * 512, VOLUME_SIZE, b"BD")


def test_a_bare_volume_starts_the_image(write_image):
    image = write_image(make_volume())

    assert hfs.find_hfs_volume(image) == (0, VOLUME_SIZE, b"BD")


def test_a_bare_hfsplus_volume_is_found_by_its_signature(write_image):
    image = write_image(make_signed_image(b"H+"))

    assert hfs.find_hfs_volume(image) == (0, 4096, b"H+")


@pytest.mark.parametrize("contents", [
    make_apm_image(make_volume(), partition_type = b"Apple_Free"),
    b"ER" + b"\0" * 2000,
    make_signed_image(b"CD"),
    b"short",
])
def test_an_image_without_an_hfs_volume_has_none(write_image, contents):
    assert hfs.find_hfs_volume(write_image(contents)) is None


def test_a_wrapper_volume_holding_hfsplus_is_recognised(write_image):
    image = write_image(make_signed_image(b"BD", embedded_signature = b"H+"))

    assert hfs.is_wrapped_hfsplus_volume(image, 0) is True


###########################################################
# Names and metadata
###########################################################

@pytest.mark.parametrize("hfs_name, local_name", [
    ("Read Me", "Read Me"),
    ("Either/Or", "Either:Or"),
    ("..", None),
    ("", None),
])
def test_mac_names_become_local_names(hfs_name, local_name):
    assert hfs.get_local_filename(hfs_name) == local_name


def test_an_unset_date_is_unknown_in_appledouble():
    assert hfs.convert_hfs_date_to_appledouble(0) == hfs.appledouble_unknown_date
    assert hfs.convert_hfs_date_to_appledouble(hfs.hfs_to_appledouble_seconds + 5) == 5


@pytest.mark.parametrize("hfs_file, needed", [
    (make_file(data = b"x"), False),
    (make_file(file_type = b"\0\0\0\0", creator = b"\0\0\0\0"), False),
    (make_file(rsrc = b"r"), True),
    (make_file(flags = 0x4000), True),
    (make_file(file_type = b"TEXT"), True),
    (make_file(creator = b"ttxt"), True),
])
def test_only_mac_metadata_needs_an_appledouble_file(hfs_file, needed):
    assert hfs.does_hfs_file_need_appledouble(hfs_file) is needed


def read_appledouble_entries(blob):
    magic, version, _, count = struct.unpack(">II16sH", blob[:26])
    entries = {}
    for index in range(count):
        entry_id, offset, length = struct.unpack(">III", blob[26 + 12 * index:38 + 12 * index])
        entries[entry_id] = blob[offset:offset + length]
    return magic, version, entries


def test_appledouble_carries_the_finder_info_dates_and_resource_fork():
    blob = hfs.build_appledouble(make_file(rsrc = b"resources", file_type = b"APPL", creator = b"PJ03", flags = 0x0100, mddate = NEW_YEAR_2005))

    magic, version, entries = read_appledouble_entries(blob)
    assert (magic, version) == (hfs.appledouble_magic, hfs.appledouble_version)
    assert entries[hfs.appledouble_entry_finder_info][:10] == b"APPLPJ03\x01\x00"
    assert len(entries[hfs.appledouble_entry_finder_info]) == 32
    assert entries[hfs.appledouble_entry_resource_fork] == b"resources"
    _, modified, backed_up, _ = struct.unpack(">iiii", entries[hfs.appledouble_entry_file_dates])
    assert modified == NEW_YEAR_2005 - hfs.hfs_to_appledouble_seconds
    assert backed_up == hfs.appledouble_unknown_date


###########################################################
# Extracting
###########################################################

def test_extracting_writes_the_data_forks_and_folders(write_image, tmp_path):
    output = tmp_path / "Game"

    assert hfs.extract_hfs(write_image(make_apm_image(make_volume())), str(output)) is True

    assert (output / "Read Me").read_bytes() == b"plain text"
    assert (output / "Start").read_bytes() == b"code"
    assert (output / "Extras" / "Either:Or").read_bytes() == b"slashed"


def test_extracting_writes_appledouble_only_beside_mac_files(write_image, tmp_path):
    output = tmp_path / "Game"
    hfs.extract_hfs(write_image(make_volume()), str(output))

    _, _, entries = read_appledouble_entries((output / "._Start").read_bytes())
    assert entries[hfs.appledouble_entry_resource_fork] == b"resources"
    assert not (output / "._Read Me").exists()


def test_extracting_keeps_the_modified_date(write_image, tmp_path):
    output = tmp_path / "Game"
    hfs.extract_hfs(write_image(make_volume()), str(output))

    assert os.path.getmtime(str(output / "Read Me")) == NEW_YEAR_2005 - hfs.hfs_to_unix_seconds


def test_extracting_deletes_the_image_when_asked(write_image, tmp_path):
    image = write_image(make_volume())

    assert hfs.extract_hfs(image, str(tmp_path / "Game"), delete_original = True, verbose = True) is True
    assert not os.path.exists(image)


def test_pretending_to_extract_writes_nothing(write_image, tmp_path):
    output = tmp_path / "Game"

    assert hfs.extract_hfs(write_image(make_volume()), str(output), pretend_run = True) is True
    assert not output.exists()


def test_an_unusable_name_is_skipped(tmp_path, caplog):
    folder = machfs.Folder()
    folder[".."] = make_file(data = b"escape")
    folder["Kept"] = make_file(data = b"kept")

    assert hfs.extract_hfs_folder(folder, str(tmp_path / "out")) is True
    assert sorted(os.listdir(str(tmp_path / "out"))) == ["Kept"]
    assert "unusable name '..'" in caplog.text


@pytest.mark.parametrize("contents, message", [
    (make_signed_image(b"CD"), "No HFS volume"),
    (make_signed_image(b"H+"), "HFS+"),
    (make_signed_image(b"BD", embedded_signature = b"H+"), "HFS+"),
    (make_signed_image(b"BD"), "Unable to read the HFS volume"),
])
def test_an_image_without_a_readable_hfs_volume_reports_failure(write_image, tmp_path, caplog, contents, message):
    assert hfs.extract_hfs(write_image(contents), str(tmp_path / "Game")) is False
    assert message in caplog.text


def test_a_missing_image_reports_failure(tmp_path):
    assert hfs.extract_hfs(str(tmp_path / "absent.iso"), str(tmp_path / "Game")) is False


def test_an_unreadable_volume_reports_failure(monkeypatch, write_image, tmp_path):
    image = write_image(make_volume())
    monkeypatch.setattr(hfs, "find_hfs_volume", lambda image_file: (VOLUME_SIZE, VOLUME_SIZE, b"BD"))

    assert hfs.extract_hfs(image, str(tmp_path / "Game")) is False


def test_extracting_without_machfs_reports_failure(monkeypatch, write_image, tmp_path, caplog):
    monkeypatch.setitem(sys.modules, "machfs", None)

    assert hfs.extract_hfs(write_image(make_volume()), str(tmp_path / "Game")) is False
    assert "machfs was not found" in caplog.text


@pytest.mark.parametrize("failing_path", ["Game", "Game/Read Me", "Game/._Start", "Game/Extras"])
def test_a_write_that_fails_stops_the_extraction(monkeypatch, write_image, tmp_path, failing_path):
    image = write_image(make_volume())
    failing = str(tmp_path / failing_path)
    make_directory, touch_file = hfs.fileops.make_directory, hfs.fileops.touch_file
    monkeypatch.setattr(hfs.fileops, "make_directory", lambda src, **kwargs: src != failing and make_directory(src, **kwargs))
    monkeypatch.setattr(hfs.fileops, "touch_file", lambda src, **kwargs: src != failing and touch_file(src, **kwargs))

    assert hfs.extract_hfs(image, str(tmp_path / "Game")) is False
