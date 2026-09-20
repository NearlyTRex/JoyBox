# Imports
import base64
import os
import zlib
import pytest

# Local imports
from joybox import playstation


###########################################################
# PlayStation content identifiers
#
# PSN files carry their content id at a fixed offset, and the renamers use it
# to name the file. Reading the wrong offset, or the wrong file, silently gives
# back nothing and the rename is skipped.
###########################################################

CONTENT_ID = "UP0001-TEST00000_00-0000000000000000"


def write_at(path, offset, value = CONTENT_ID, size = 0x24):
    payload = bytearray(os.urandom(offset + size + 64))
    payload[offset:offset + size] = value.encode("utf-8").ljust(size, b"\x00")
    with open(str(path), "wb") as handle:
        handle.write(bytes(payload))
    return str(path)


###########################################################
# Offsets
#
# Each file type keeps its content id somewhere different.
###########################################################

@pytest.mark.parametrize("reader,offset", [
    (playstation.get_psn_package_content_id, 0x30),
    (playstation.get_psn_workbin_content_id, 0x10),
    (playstation.get_psn_fakerif_content_id, 0x50),
])
def test_a_content_id_is_read_from_its_own_offset(tmp_path, reader, offset):
    source = write_at(tmp_path / "file.bin", offset)

    assert reader(source) == CONTENT_ID


@pytest.mark.parametrize("reader,offset", [
    (playstation.get_psn_package_content_id, 0x30),
    (playstation.get_psn_workbin_content_id, 0x10),
    (playstation.get_psn_fakerif_content_id, 0x50),
])
def test_a_reader_reads_the_file_it_was_given(tmp_path, reader, offset):
    # A reader that opens a different variable always returns nothing, and the
    # bare except hides it.
    first = write_at(tmp_path / "first.bin", offset, "UP0001-FIRST0000_00-0000000000000000")
    second = write_at(tmp_path / "second.bin", offset, "UP0001-SECOND000_00-0000000000000000")

    assert reader(first) == "UP0001-FIRST0000_00-0000000000000000"
    assert reader(second) == "UP0001-SECOND000_00-0000000000000000"


def test_the_readers_use_distinct_offsets(tmp_path):
    # One id placed at the package offset must not be found by the others.
    source = write_at(tmp_path / "file.bin", 0x30)

    assert playstation.get_psn_package_content_id(source) == CONTENT_ID
    assert playstation.get_psn_workbin_content_id(source) != CONTENT_ID
    assert playstation.get_psn_fakerif_content_id(source) != CONTENT_ID


@pytest.mark.parametrize("reader", [
    playstation.get_psn_package_content_id,
    playstation.get_psn_workbin_content_id,
    playstation.get_psn_fakerif_content_id,
])
def test_a_missing_file_yields_nothing(tmp_path, reader):
    assert reader(str(tmp_path / "absent.bin")) is None


@pytest.mark.parametrize("reader", [
    playstation.get_psn_package_content_id,
    playstation.get_psn_workbin_content_id,
    playstation.get_psn_fakerif_content_id,
])
def test_a_truncated_file_yields_nothing_or_a_short_id(tmp_path, reader):
    target = tmp_path / "short.bin"
    target.write_bytes(b"\x00" * 8)
    result = reader(str(target))

    assert result is None or len(result) < 0x24


@pytest.mark.parametrize("reader", [
    playstation.get_psn_package_content_id,
    playstation.get_psn_workbin_content_id,
    playstation.get_psn_fakerif_content_id,
])
def test_undecodable_bytes_yield_nothing(tmp_path, reader):
    target = tmp_path / "binary.bin"
    target.write_bytes(b"\xff" * 512)

    assert reader(str(target)) is None


###########################################################
# Renaming
###########################################################

def test_a_fake_rif_is_renamed_to_its_content_id(tmp_path):
    source = tmp_path / "unknown.fake.rif"
    write_at(source, 0x50)

    assert playstation.rename_psn_fakerif_file(str(source)) is True
    assert (tmp_path / (CONTENT_ID + ".fake.rif")).exists()
    assert not source.exists()


def test_a_work_bin_is_renamed_to_its_content_id(tmp_path):
    source = tmp_path / "unknown.work.bin"
    write_at(source, 0x10)

    assert playstation.rename_psn_workbin_file(str(source)) is True
    assert (tmp_path / (CONTENT_ID + ".work.bin")).exists()


def test_a_package_is_renamed_to_its_content_id(tmp_path):
    source = tmp_path / "unknown.pkg"
    write_at(source, 0x30)

    assert playstation.rename_psn_package_file(str(source)) is True
    assert (tmp_path / (CONTENT_ID + ".pkg")).exists()


@pytest.mark.parametrize("renamer,suffix", [
    (playstation.rename_psn_fakerif_file, ".fake.rif"),
    (playstation.rename_psn_workbin_file, ".work.bin"),
    (playstation.rename_psn_package_file, ".pkg"),
])
def test_a_file_without_a_content_id_is_not_renamed(tmp_path, renamer, suffix):
    source = tmp_path / ("unknown" + suffix)
    source.write_bytes(b"\xff" * 512)

    assert renamer(str(source)) is False
    assert source.exists()


@pytest.mark.parametrize("renamer,suffix", [
    (playstation.rename_psn_fakerif_file, ".fake.rif"),
    (playstation.rename_psn_workbin_file, ".work.bin"),
    (playstation.rename_psn_package_file, ".pkg"),
])
def test_a_missing_file_is_not_renamed(tmp_path, renamer, suffix):
    assert renamer(str(tmp_path / ("absent" + suffix))) is False


def test_a_rename_keeps_the_file_in_its_directory(tmp_path):
    nested = tmp_path / "psn" / "vita"
    nested.mkdir(parents = True)
    source = nested / "unknown.fake.rif"
    write_at(source, 0x50)
    playstation.rename_psn_fakerif_file(str(source))

    assert (nested / (CONTENT_ID + ".fake.rif")).exists()


def test_renaming_an_already_named_file_is_harmless(tmp_path):
    source = tmp_path / (CONTENT_ID + ".fake.rif")
    write_at(source, 0x50)
    playstation.rename_psn_fakerif_file(str(source))

    assert source.exists()


###########################################################
# zRIF decoding
###########################################################

def encode_zrif(payload):
    # The inverse of the decoder, using the same seeded dictionary.
    zrif_base64 = (b"eNpjYBgFo2AU0AsYAIElGt8MRJiDCAsw3xhEmIAIU4N4AwNdRxcXZ3+/EJCAkW6Ac7C7ARwYgviuQAaIdoPSzlDaBUo7QmknIM3ACIZM78+u7kx3VWYEAGJ9HV0=")
    dictionary = zlib.decompress(base64.b64decode(zrif_base64))
    compressor = zlib.compressobj(9, zlib.DEFLATED, 10, zdict = dictionary)
    data = compressor.compress(payload) + compressor.flush()
    return base64.b64encode(data).decode("ascii")


def test_a_zrif_string_decodes_to_its_bytes():
    payload = bytes(range(256)) * 2

    assert playstation.get_psn_workbin_bytes_from_zrif_string(encode_zrif(payload)) == payload


def test_a_zrif_round_trip_survives_a_licence_sized_payload():
    payload = os.urandom(512)

    assert playstation.get_psn_workbin_bytes_from_zrif_string(encode_zrif(payload)) == payload


@pytest.mark.parametrize("value", ["not-base64!", "AAAA", "x" * 40])
def test_an_invalid_zrif_string_decodes_to_nothing(value):
    assert playstation.get_psn_workbin_bytes_from_zrif_string(value) is None


def test_an_empty_zrif_string_decodes_to_nothing_usable():
    # Empty in, empty out; callers test the result for content either way.
    assert not playstation.get_psn_workbin_bytes_from_zrif_string("")


###########################################################
# PS3 decryption keys
###########################################################

def test_a_decryption_key_is_read(tmp_path):
    target = tmp_path / "game.dkey"
    target.write_text("0123456789ABCDEF0123456789ABCDEF")

    assert playstation.get_ps3_decryption_key(str(target)) == \
        "0123456789ABCDEF0123456789ABCDEF"


def test_a_decryption_key_is_stripped(tmp_path):
    # Redump dkey files carry a trailing newline, which ps3dec rejects.
    target = tmp_path / "game.dkey"
    target.write_text("  0123456789ABCDEF0123456789ABCDEF \n")

    assert playstation.get_ps3_decryption_key(str(target)) == \
        "0123456789ABCDEF0123456789ABCDEF"


def test_a_missing_key_file_reads_as_empty(tmp_path):
    assert playstation.get_ps3_decryption_key(str(tmp_path / "absent.dkey")) == ""


def test_an_empty_key_file_reads_as_empty(tmp_path):
    target = tmp_path / "game.dkey"
    target.write_text("\n")

    assert playstation.get_ps3_decryption_key(str(target)) == ""
