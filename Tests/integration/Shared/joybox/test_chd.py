# Imports
import os
import pytest

# Local imports
from joybox import chd, iso

pytestmark = [
    pytest.mark.requires_tool("MameChdman"),
    pytest.mark.requires_tool("XorrISO"),
    pytest.mark.slow,
]


###########################################################
# CHD round trip
#
# Runs the real chdman. A directory of random bytes is a valid ISO payload, so
# the whole create -> verify -> extract path can be exercised without a game
# image.
###########################################################

@pytest.fixture
def payload(tmp_path):
    source = tmp_path / "payload"
    source.mkdir()
    (source / "data.bin").write_bytes(os.urandom(400000))
    (source / "readme.txt").write_text("test payload\n")
    return source


@pytest.fixture
def source_iso(tmp_path, payload, requires_tool):
    target = tmp_path / "source.iso"
    assert iso.create_iso(str(target), source_dir = str(payload)) is True
    return target


@pytest.fixture
def source_chd(tmp_path, source_iso):
    target = tmp_path / "game.chd"
    assert chd.create_disc_chd(str(target), str(source_iso)) is True
    return target


###########################################################
# Creating
###########################################################

def test_a_chd_is_created_from_an_iso(source_chd):
    assert source_chd.exists()
    assert source_chd.stat().st_size > 0


def test_a_created_chd_is_smaller_than_its_source(source_chd, source_iso):
    # Compression is the whole point; an uncompressed result means chdman fell
    # back to raw and the archive gains nothing.
    assert source_chd.stat().st_size < source_iso.stat().st_size


def test_a_created_chd_carries_the_chd_magic(source_chd):
    assert source_chd.read_bytes()[:8] == b"MComprHD"


def test_creating_from_a_missing_iso_reports_failure(tmp_path):
    target = tmp_path / "game.chd"

    assert chd.create_disc_chd(str(target), str(tmp_path / "absent.iso")) is False
    assert not target.exists()


def test_creating_from_a_non_iso_reports_failure(tmp_path):
    source = tmp_path / "notanimage.iso"
    source.write_text("this is not a disc image")
    target = tmp_path / "game.chd"

    assert chd.create_disc_chd(str(target), str(source)) is False


def test_a_failed_create_leaves_the_source_alone(tmp_path):
    source = tmp_path / "notanimage.iso"
    source.write_text("this is not a disc image")
    chd.create_disc_chd(str(tmp_path / "game.chd"), str(source), delete_original = True)

    assert source.exists()


def test_a_successful_create_deletes_the_source_when_asked(tmp_path, source_iso):
    target = tmp_path / "game.chd"

    assert chd.create_disc_chd(str(target), str(source_iso), delete_original = True) is True
    assert not source_iso.exists()
    assert target.exists()


def test_pretending_creates_nothing(tmp_path, source_iso):
    target = tmp_path / "game.chd"
    chd.create_disc_chd(str(target), str(source_iso), pretend_run = True)

    assert not target.exists()


###########################################################
# Verifying
###########################################################

def test_a_created_chd_verifies(source_chd):
    assert chd.verify_disc_chd(str(source_chd)) is True


def test_a_truncated_chd_fails_verification(tmp_path, source_chd):
    data = source_chd.read_bytes()
    source_chd.write_bytes(data[:len(data) // 2])

    assert chd.verify_disc_chd(str(source_chd)) is False


def test_a_corrupted_chd_fails_verification(tmp_path, source_chd):
    # A flipped byte in the payload is what bit rot looks like on the storage
    # box, and is exactly what the hash check exists to catch.
    data = bytearray(source_chd.read_bytes())
    data[-100] ^= 0xFF
    source_chd.write_bytes(bytes(data))

    assert chd.verify_disc_chd(str(source_chd)) is False


def test_verifying_a_missing_chd_reports_failure(tmp_path):
    assert chd.verify_disc_chd(str(tmp_path / "absent.chd")) is False


###########################################################
# Extracting
###########################################################

def test_a_chd_extracts_back_to_its_source_bytes(tmp_path, source_chd, source_iso):
    binary = tmp_path / "out.bin"
    toc = tmp_path / "out.toc"

    assert chd.extract_disc_chd(str(source_chd), str(binary), str(toc)) is True
    original = source_iso.read_bytes()
    assert binary.read_bytes()[:len(original)] == original


def test_extracting_writes_both_artifacts(tmp_path, source_chd):
    binary = tmp_path / "out.bin"
    toc = tmp_path / "out.toc"
    chd.extract_disc_chd(str(source_chd), str(binary), str(toc))

    assert binary.exists()
    assert toc.exists()
    assert toc.stat().st_size > 0


def test_an_extracted_toc_names_its_binary(tmp_path, source_chd):
    binary = tmp_path / "out.bin"
    toc = tmp_path / "out.toc"
    chd.extract_disc_chd(str(source_chd), str(binary), str(toc))

    assert "out.bin" in toc.read_text()


def test_extracting_a_missing_chd_reports_failure(tmp_path):
    assert chd.extract_disc_chd(
        str(tmp_path / "absent.chd"), str(tmp_path / "o.bin"), str(tmp_path / "o.toc")) is False


def test_a_full_round_trip_survives_a_second_pass(tmp_path, source_chd):
    # Re-compressing an extracted image must land on the same bytes, or the
    # archive drifts every time a disc is reprocessed. The toc is what carries
    # the track layout, so that is what goes back in, not the bare binary.
    binary = tmp_path / "out.bin"
    toc = tmp_path / "out.toc"
    chd.extract_disc_chd(str(source_chd), str(binary), str(toc))

    second = tmp_path / "second.chd"
    assert chd.create_disc_chd(str(second), str(toc)) is True

    again = tmp_path / "again.bin"
    assert chd.extract_disc_chd(
        str(second), str(again), str(tmp_path / "again.toc")) is True
    assert again.read_bytes() == binary.read_bytes()
