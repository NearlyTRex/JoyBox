# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import hashing
from hashing_helpers import expected_digests, write_file


###########################################################
# File digests
#
# These are what an archive's integrity is judged against, so they have to
# agree with the reference implementations and be stable across chunk sizes.
###########################################################

PAYLOAD = b"The quick brown fox jumps over the lazy dog"

FUNCTIONS = {
    "crc32": hashing.calculate_file_crc32,
    "md5": hashing.calculate_file_md5,
    "sha1": hashing.calculate_file_sha1,
    "sha256": hashing.calculate_file_sha256,
}


@pytest.fixture
def payload_file(tmp_path):
    return write_file(tmp_path, "payload.bin", PAYLOAD)


###########################################################
# Correctness
###########################################################

@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_a_digest_matches_the_reference_implementation(payload_file, name):
    assert FUNCTIONS[name](payload_file) == expected_digests(PAYLOAD)[name]


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_an_empty_file_still_produces_a_digest(tmp_path, name):
    empty = write_file(tmp_path, "empty.bin", b"")

    assert FUNCTIONS[name](empty) == expected_digests(b"")[name]


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_the_chunk_size_does_not_change_the_digest(payload_file, name):
    # A file larger than one chunk takes the loop rather than a single read
    whole = FUNCTIONS[name](payload_file)

    assert FUNCTIONS[name](payload_file, chunksize = 1) == whole
    assert FUNCTIONS[name](payload_file, chunksize = 7) == whole


def test_xxh3_is_stable_across_chunk_sizes(payload_file):
    pytest.importorskip("xxhash")

    whole = hashing.calculate_file_xxh3(payload_file)

    assert whole
    assert hashing.calculate_file_xxh3(payload_file, chunksize = 3) == whole


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_different_contents_produce_different_digests(tmp_path, name):
    first = write_file(tmp_path, "first.bin", b"one")
    second = write_file(tmp_path, "second.bin", b"two")

    assert FUNCTIONS[name](first) != FUNCTIONS[name](second)


def test_a_crc32_is_rendered_the_way_a_dat_file_stores_one(payload_file):
    # Eight lowercase hex digits, no prefix - so it can be compared against a
    # dat entry without reformatting either side
    value = hashing.calculate_file_crc32(payload_file)

    assert len(value) == 8
    assert not value.startswith("0x")
    assert value == value.lower()


def test_a_crc32_with_leading_zeros_keeps_its_width(tmp_path):
    # "%x" would drop them, giving a checksum narrower than any dat carries
    for index in range(600):
        candidate = write_file(tmp_path, "probe.bin", b"x" * index)
        if hashing.calculate_file_crc32(candidate).startswith("0"):
            assert len(hashing.calculate_file_crc32(candidate)) == 8
            return
    pytest.skip("no short crc32 found to pad")


###########################################################
# Failure and pretend runs
###########################################################

@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_a_missing_file_digests_to_nothing(tmp_path, name):
    assert FUNCTIONS[name](os.path.join(str(tmp_path), "absent.bin")) == ""


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_a_pretend_run_reads_nothing(payload_file, name):
    assert FUNCTIONS[name](payload_file, pretend_run = True) == ""


def test_a_pretend_run_does_not_need_the_file_to_exist(tmp_path):
    absent = os.path.join(str(tmp_path), "absent.bin")

    assert hashing.calculate_file_md5(absent, pretend_run = True) == ""


def test_a_directory_digests_to_nothing(tmp_path):
    assert hashing.calculate_file_md5(str(tmp_path)) == ""
