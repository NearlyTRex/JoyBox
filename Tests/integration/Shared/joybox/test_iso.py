# Imports
import os
import pytest

# Local imports
from joybox import iso

pytestmark = [pytest.mark.requires_tool("XorrISO"), pytest.mark.slow]


###########################################################
# ISO round trip
#
# Runs the real xorriso. Arbitrary files make a valid payload, so the create
# and extract paths can be exercised without a game disc.
###########################################################

@pytest.fixture
def payload(tmp_path):
    source = tmp_path / "payload"
    (source / "nested" / "deeper").mkdir(parents = True)
    (source / "data.bin").write_bytes(os.urandom(200000))
    (source / "readme.txt").write_text("test payload\n")
    (source / "nested" / "inner.txt").write_text("inner\n")
    (source / "nested" / "deeper" / "deep.txt").write_text("deep\n")
    return source


@pytest.fixture
def built_iso(tmp_path, payload, requires_tool):
    target = tmp_path / "game.iso"
    assert iso.create_iso(str(target), source_dir = str(payload)) is True
    return target


def extracted(tmp_path, image, name = "out"):
    target = tmp_path / name
    assert iso.extract_iso(str(image), str(target)) is True
    return target


###########################################################
# Creating
###########################################################

def test_an_iso_is_created(built_iso):
    assert built_iso.exists()
    assert built_iso.stat().st_size > 0


def test_a_created_iso_carries_the_iso9660_signature(built_iso):
    # "CD001" at the start of the primary volume descriptor, sector 16.
    with open(str(built_iso), "rb") as handle:
        handle.seek(16 * 2048 + 1)
        assert handle.read(5) == b"CD001"


def test_a_volume_name_reaches_the_image(tmp_path, payload, requires_tool):
    target = tmp_path / "game.iso"
    iso.create_iso(str(target), source_dir = str(payload), volume_name = "GAMEDISC")

    with open(str(target), "rb") as handle:
        handle.seek(16 * 2048 + 40)
        assert handle.read(8) == b"GAMEDISC"


def test_creating_from_a_missing_directory_reports_failure(tmp_path, requires_tool):
    target = tmp_path / "game.iso"
    iso.create_iso(str(target), source_dir = str(tmp_path / "absent"))

    assert not target.exists() or target.stat().st_size == 0


def test_several_source_directories_all_reach_the_image(tmp_path, requires_tool):
    # The extra sources were silently dropped, producing an empty image.
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "one.txt").write_text("one\n")
    (second / "two.txt").write_text("two\n")

    target = tmp_path / "game.iso"
    assert iso.create_iso(str(target), source_dirs = [str(first), str(second)]) is True

    out = extracted(tmp_path, target)
    names = {path.name for path in out.rglob("*") if path.is_file()}
    assert {"one.txt", "two.txt"} <= names


def test_a_successful_create_deletes_the_source_when_asked(tmp_path, payload, requires_tool):
    target = tmp_path / "game.iso"

    assert iso.create_iso(
        str(target), source_dir = str(payload), delete_original = True) is True
    assert not payload.exists()


def test_pretending_creates_nothing(tmp_path, payload, requires_tool):
    target = tmp_path / "game.iso"
    iso.create_iso(str(target), source_dir = str(payload), pretend_run = True)

    assert not target.exists()


###########################################################
# Extracting
###########################################################

def test_an_iso_extracts_its_files(tmp_path, built_iso):
    out = extracted(tmp_path, built_iso)
    names = {path.name for path in out.rglob("*") if path.is_file()}

    assert {"data.bin", "readme.txt", "inner.txt", "deep.txt"} <= names


def test_extracted_content_matches_the_payload(tmp_path, built_iso, payload):
    out = extracted(tmp_path, built_iso)
    original = (payload / "data.bin").read_bytes()
    restored = [path for path in out.rglob("data.bin")][0]

    assert restored.read_bytes() == original


def test_nesting_survives_the_round_trip(tmp_path, built_iso):
    # iso-level 3 plus joliet is what keeps deep paths intact.
    out = extracted(tmp_path, built_iso)
    deep = [path for path in out.rglob("deep.txt")]

    assert len(deep) == 1
    assert deep[0].read_text() == "deep\n"


def test_a_long_filename_survives_the_round_trip(tmp_path, requires_tool):
    source = tmp_path / "payload"
    source.mkdir()
    long_name = "Final Fantasy VII (USA) (Disc 1) (Rev 1) - patched.bin"
    (source / long_name).write_text("content\n")

    target = tmp_path / "game.iso"
    assert iso.create_iso(str(target), source_dir = str(source)) is True

    out = extracted(tmp_path, target)
    assert any(path.name == long_name for path in out.rglob("*"))


def test_extracted_files_are_readable(tmp_path, built_iso):
    # Files come off an iso read only, and the wrapper resets permissions so a
    # later transform can write to them.
    out = extracted(tmp_path, built_iso)
    for path in out.rglob("*"):
        if path.is_file():
            assert os.access(str(path), os.R_OK)


def test_extracting_a_missing_image_reports_failure(tmp_path, requires_tool):
    assert iso.extract_iso(str(tmp_path / "absent.iso"), str(tmp_path / "out")) is False


def test_extracting_a_non_image_reports_failure(tmp_path, requires_tool):
    source = tmp_path / "notanimage.iso"
    source.write_text("this is not a disc image")

    assert iso.extract_iso(str(source), str(tmp_path / "out")) is False


def test_a_round_trip_is_stable(tmp_path, built_iso, payload):
    # Rebuilding from extracted content must hold the same files, or a library
    # loses entries each time an image is reprocessed.
    out = extracted(tmp_path, built_iso)
    second = tmp_path / "second.iso"
    assert iso.create_iso(str(second), source_dir = str(out)) is True

    again = extracted(tmp_path, second, name = "again")
    first_names = {path.name for path in out.rglob("*") if path.is_file()}
    second_names = {path.name for path in again.rglob("*") if path.is_file()}
    assert first_names == second_names
