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


###########################################################
# Tool wrappers
#
# Every wrapper builds an argument list for a tool that is not installed here.
# Recording the list pins the invocation: a mode flag in the wrong place, or a
# key that never reaches the command, only shows up on a real disc image.
###########################################################

TOOL_PATHS = {
    "PS3Dec": "/tools/ps3dec",
    "PSVStrip": "/tools/psvstrip",
    "PSVTools": "/tools/psvtools.py",
    "PSNGetPkgInfo": "/tools/psngetpkginfo.py",
    "PythonVenvPython": "/tools/venv/python",
}


@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(playstation.programs, "is_tool_installed", lambda name: name in TOOL_PATHS)
    monkeypatch.setattr(playstation.programs, "get_tool_program", lambda name: TOOL_PATHS.get(name))
    return TOOL_PATHS


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(playstation.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(playstation.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def existing_output(monkeypatch):
    monkeypatch.setattr(playstation.os.path, "exists", lambda path: True)


@pytest.fixture
def key_file(tmp_path):
    target = tmp_path / "game.dkey"
    target.write_text("0123456789ABCDEF0123456789ABCDEF")
    return str(target)


###########################################################
# PS3 encryption and decryption
###########################################################

def test_encrypting_uses_the_encrypt_mode(installed, recording_command, existing_output, key_file):
    playstation.encrypt_ps3_iso("/in/Game.dec.iso", "/out/Game.iso", key_file)

    assert recording_command.only()[:2] == ["/tools/ps3dec", "e"]


def test_decrypting_uses_the_decrypt_mode(installed, recording_command, existing_output, key_file):
    # The mode is a bare positional, so encrypt and decrypt differ by one
    # token and a swap silently produces garbage.
    playstation.decrypt_ps3_iso("/in/Game.iso", "/out/Game.dec.iso", key_file)

    assert recording_command.only()[:2] == ["/tools/ps3dec", "d"]


@pytest.mark.parametrize("wrapper", [
    playstation.encrypt_ps3_iso,
    playstation.decrypt_ps3_iso,
])
def test_the_key_from_the_file_is_passed(installed, recording_command, existing_output, key_file, wrapper):
    wrapper("/in/Game.iso", "/out/Game.dec.iso", key_file)

    assert recording_command.value_after("key") == "0123456789ABCDEF0123456789ABCDEF"


@pytest.mark.parametrize("wrapper", [
    playstation.encrypt_ps3_iso,
    playstation.decrypt_ps3_iso,
])
def test_the_images_are_passed_in_order(installed, recording_command, existing_output, key_file, wrapper):
    wrapper("/in/Game.iso", "/out/Game.dec.iso", key_file)

    assert recording_command.only()[-2:] == ["/in/Game.iso", "/out/Game.dec.iso"]


@pytest.mark.parametrize("wrapper", [
    playstation.encrypt_ps3_iso,
    playstation.decrypt_ps3_iso,
])
def test_working_without_ps3dec_reports_failure(missing, recording_command, key_file, wrapper):
    assert wrapper("/in/Game.iso", "/out/Game.dec.iso", key_file) is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper", [
    playstation.encrypt_ps3_iso,
    playstation.decrypt_ps3_iso,
])
def test_an_empty_key_file_stops_before_the_tool_runs(installed, recording_command, tmp_path, wrapper):
    # ps3dec takes the key as a positional; an empty one shifts every argument
    # that follows it.
    empty = tmp_path / "empty.dkey"
    empty.write_text("\n")

    assert wrapper("/in/Game.iso", "/out/Game.dec.iso", str(empty)) is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper", [
    playstation.encrypt_ps3_iso,
    playstation.decrypt_ps3_iso,
])
def test_an_empty_key_file_can_quit_the_program(installed, recording_command, tmp_path, wrapper):
    empty = tmp_path / "empty.dkey"
    empty.write_text("")

    with pytest.raises(SystemExit):
        wrapper("/in/Game.iso", "/out/Game.dec.iso", str(empty), exit_on_failure = True)


@pytest.mark.parametrize("wrapper", [
    playstation.encrypt_ps3_iso,
    playstation.decrypt_ps3_iso,
])
def test_a_failed_conversion_reports_failure(installed, monkeypatch, key_file, wrapper):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert wrapper("/in/Game.iso", "/out/Game.dec.iso", key_file) is False


@pytest.mark.parametrize("wrapper", [
    playstation.encrypt_ps3_iso,
    playstation.decrypt_ps3_iso,
])
def test_a_failed_conversion_can_quit_the_program(installed, monkeypatch, key_file, wrapper):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    with pytest.raises(SystemExit):
        wrapper("/in/Game.iso", "/out/Game.dec.iso", key_file, exit_on_failure = True)


@pytest.mark.parametrize("wrapper", [
    playstation.encrypt_ps3_iso,
    playstation.decrypt_ps3_iso,
])
def test_a_missing_result_reports_failure(installed, recording_command, key_file, wrapper, tmp_path):
    # The tool can return zero and still write nothing, so the result is
    # checked rather than trusted.
    assert wrapper("/in/Game.iso", str(tmp_path / "absent.iso"), key_file) is False


###########################################################
# Extracting a PS3 image
###########################################################

@pytest.fixture
def decrypted(monkeypatch):
    # Records what the decrypt step was asked for, without a tool or an image.
    calls = []

    def decrypt_ps3_iso(iso_file_enc, iso_file_dec, dkey_file, **kwargs):
        calls.append({"enc": iso_file_enc, "dec": iso_file_dec, "dkey": dkey_file})
        return True

    monkeypatch.setattr(playstation, "decrypt_ps3_iso", decrypt_ps3_iso)
    return calls


@pytest.fixture
def extracted(monkeypatch, tmp_path):
    # Stands in for the real extractor, laying down the two files whose
    # headers decide whether the decryption key was the right one.
    extract_dir = tmp_path / "extracted"

    def extract_iso(iso_file, extract_dir, **kwargs):
        usrdir = os.path.join(extract_dir, "PS3_GAME", "USRDIR")
        licdir = os.path.join(extract_dir, "PS3_GAME", "LICDIR")
        os.makedirs(usrdir, exist_ok = True)
        os.makedirs(licdir, exist_ok = True)
        with open(os.path.join(licdir, "LIC.DAT"), "wb") as handle:
            handle.write(b"PS3LICDA" + os.urandom(64))
        with open(os.path.join(usrdir, "EBOOT.BIN"), "wb") as handle:
            handle.write(b"SCE" + os.urandom(64))
        return True

    monkeypatch.setattr(playstation.iso, "extract_iso", extract_iso)
    return str(extract_dir)


def test_extracting_decrypts_beside_the_source(decrypted, extracted, key_file):
    # The decrypted copy lands next to the image rather than in the working
    # directory, which is where the extractor then looks for it.
    playstation.extract_ps3_iso("/in/Game.iso", key_file, extracted)

    assert decrypted[0]["dec"] == os.path.join("/in", "Game.dec.iso")
    assert decrypted[0]["enc"] == "/in/Game.iso"


def test_extracting_passes_the_key_through(decrypted, extracted, key_file):
    playstation.extract_ps3_iso("/in/Game.iso", key_file, extracted)

    assert decrypted[0]["dkey"] == key_file


def test_extracting_a_correctly_decrypted_image_succeeds(decrypted, extracted, key_file):
    assert playstation.extract_ps3_iso("/in/Game.iso", key_file, extracted) is True


def test_extracting_reads_the_decrypted_copy(decrypted, monkeypatch, tmp_path, key_file):
    seen = {}

    def extract_iso(iso_file, extract_dir, **kwargs):
        seen["iso"] = iso_file
        os.makedirs(extract_dir, exist_ok = True)
        return True

    monkeypatch.setattr(playstation.iso, "extract_iso", extract_iso)
    playstation.extract_ps3_iso("/in/Game.iso", key_file, str(tmp_path / "out"))

    assert seen["iso"] == os.path.join("/in", "Game.dec.iso")


def test_a_failed_decryption_does_not_extract(installed, monkeypatch, key_file, tmp_path):
    monkeypatch.setattr(playstation, "decrypt_ps3_iso", lambda **kwargs: False)

    def fail(*args, **kwargs):
        raise AssertionError("an undecrypted image must not be extracted")

    monkeypatch.setattr(playstation.iso, "extract_iso", fail)

    assert playstation.extract_ps3_iso("/in/Game.iso", key_file, str(tmp_path / "out")) is False


def test_a_failed_extraction_reports_failure(decrypted, monkeypatch, key_file, tmp_path):
    monkeypatch.setattr(playstation.iso, "extract_iso", lambda **kwargs: False)

    assert playstation.extract_ps3_iso("/in/Game.iso", key_file, str(tmp_path / "out")) is False


@pytest.mark.parametrize("target", [
    os.path.join("PS3_GAME", "LICDIR", "LIC.DAT"),
    os.path.join("PS3_GAME", "USRDIR", "EBOOT.BIN"),
])
def test_a_wrong_header_reports_a_bad_key(decrypted, monkeypatch, tmp_path, key_file, target):
    # A mismatched dkey decrypts to noise rather than failing outright, and
    # these two headers are how that is caught.
    extract_dir = str(tmp_path / "extracted")

    def extract_iso(iso_file, extract_dir, **kwargs):
        for name, header in [
            (os.path.join("PS3_GAME", "LICDIR", "LIC.DAT"), b"PS3LICDA"),
            (os.path.join("PS3_GAME", "USRDIR", "EBOOT.BIN"), b"SCE"),
        ]:
            path = os.path.join(extract_dir, name)
            os.makedirs(os.path.dirname(path), exist_ok = True)
            with open(path, "wb") as handle:
                handle.write((os.urandom(8) if name == target else header) + os.urandom(64))
        return True

    monkeypatch.setattr(playstation.iso, "extract_iso", extract_iso)

    assert playstation.extract_ps3_iso("/in/Game.iso", key_file, extract_dir) is False


def test_a_wrong_header_can_quit_the_program(decrypted, extracted, key_file, monkeypatch):
    monkeypatch.setattr(playstation.fileops, "is_file_correctly_headered", lambda src, header: False)

    with pytest.raises(SystemExit):
        playstation.extract_ps3_iso("/in/Game.iso", key_file, extracted, exit_on_failure = True)


def test_an_image_without_those_files_is_not_judged_by_them(decrypted, monkeypatch, tmp_path, key_file):
    # Not every PS3 image carries a LIC.DAT, and a missing one is not a
    # decryption failure.
    def extract_iso(iso_file, extract_dir, **kwargs):
        os.makedirs(extract_dir, exist_ok = True)
        return True

    monkeypatch.setattr(playstation.iso, "extract_iso", extract_iso)

    assert playstation.extract_ps3_iso("/in/Game.iso", key_file, str(tmp_path / "out")) is True


def test_extracting_can_remove_the_decrypted_copy(decrypted, extracted, key_file, monkeypatch):
    # The decrypted image is twice the size of the source and is scratch data.
    removed = []
    monkeypatch.setattr(playstation.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    playstation.extract_ps3_iso("/in/Game.iso", key_file, extracted, delete_original = True)

    assert removed == [os.path.join("/in", "Game.dec.iso")]


def test_extracting_keeps_the_decrypted_copy_by_default(decrypted, extracted, key_file, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("nothing may be removed unless deletion was asked for")

    monkeypatch.setattr(playstation.fileops, "remove_file", fail)

    playstation.extract_ps3_iso("/in/Game.iso", key_file, extracted)


###########################################################
# Verifying a PS3 CHD
###########################################################

def test_verifying_a_chd_looks_for_the_key_beside_it(installed, recording_command, monkeypatch, tmp_path):
    seen = {}

    def extract_disc_chd(chd_file, binary_file, toc_file, **kwargs):
        seen["binary"] = binary_file
        return True

    def extract_ps3_iso(iso_file, dkey_file, extract_dir, **kwargs):
        seen["dkey"] = dkey_file
        return True

    monkeypatch.setattr(playstation.chd, "extract_disc_chd", extract_disc_chd)
    monkeypatch.setattr(playstation, "extract_ps3_iso", extract_ps3_iso)

    assert playstation.verify_ps3_chd(str(tmp_path / "Game.chd")) is True
    assert seen["dkey"] == str(tmp_path / "Game.dkey")


def test_a_chd_that_will_not_extract_is_not_verified(installed, monkeypatch, tmp_path):
    monkeypatch.setattr(playstation.chd, "extract_disc_chd", lambda **kwargs: False)

    def fail(*args, **kwargs):
        raise AssertionError("an unextracted chd must not be decrypted")

    monkeypatch.setattr(playstation, "extract_ps3_iso", fail)

    assert playstation.verify_ps3_chd(str(tmp_path / "Game.chd")) is False


def test_an_image_that_will_not_decrypt_is_not_verified(installed, monkeypatch, tmp_path):
    monkeypatch.setattr(playstation.chd, "extract_disc_chd", lambda **kwargs: True)
    monkeypatch.setattr(playstation, "extract_ps3_iso", lambda **kwargs: False)

    assert playstation.verify_ps3_chd(str(tmp_path / "Game.chd")) is False


###########################################################
# PSN packages
###########################################################

def test_extracting_a_package_names_the_content_directory(installed, recording_command, existing_output):
    playstation.extract_psn_pkg("/in/Game.pkg", "/out")

    assert recording_command.value_after("--content") == "/out"


def test_extracting_a_package_runs_the_script_under_the_venv(installed, recording_command, existing_output):
    # The script is not executable on its own; it is handed to the interpreter.
    playstation.extract_psn_pkg("/in/Game.pkg", "/out")

    assert recording_command.only()[:2] == ["/tools/venv/python", "/tools/psngetpkginfo.py"]


def test_extracting_a_package_passes_it_last(installed, recording_command, existing_output):
    playstation.extract_psn_pkg("/in/Game.pkg", "/out")

    assert recording_command.only()[-1] == "/in/Game.pkg"


def test_extracting_a_package_without_the_tool_reports_failure(missing, recording_command):
    assert playstation.extract_psn_pkg("/in/Game.pkg", "/out") is False
    assert recording_command.ran() is False


def test_a_failed_package_extract_reports_failure(installed, monkeypatch):
    # A run that was not told to exit carries on to the next package.
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert playstation.extract_psn_pkg("/in/Game.pkg", "/out") is False


def test_a_failed_package_extract_can_quit_the_program(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    with pytest.raises(SystemExit):
        playstation.extract_psn_pkg("/in/Game.pkg", "/out", exit_on_failure = True)


def test_extracting_a_package_can_remove_it(installed, recording_command, existing_output, monkeypatch):
    removed = []
    monkeypatch.setattr(playstation.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    playstation.extract_psn_pkg("/in/Game.pkg", "/out", delete_original = True)

    assert removed == ["/in/Game.pkg"]


###########################################################
# PSN package information
###########################################################

INFO_OUTPUT = "\n".join([
    "NPS Type: PSV GAME",
    "Title ID: PCSE00123",
    "Title: A Game",
    "Region: USA",
    "Content ID: UP0001-PCSE00123_00-0000000000000000",
    "Content Type: 21",
    "DRM Type: 3",
    "Min FW: 3.60",
    "Version: 1.00",
    "App Ver: 1.01",
    "Size: 123456",
])


def info_command(monkeypatch, output):
    from fakes import RecordingCommand
    return RecordingCommand(monkeypatch, output = output)


def test_every_known_field_is_parsed(installed, monkeypatch):
    info_command(monkeypatch, INFO_OUTPUT)

    info = playstation.get_psn_package_info("/in/Game.pkg")

    assert info == {
        "nps_type": "PSV GAME",
        "title_id": "PCSE00123",
        "title": "A Game",
        "region": "USA",
        "content_id": "UP0001-PCSE00123_00-0000000000000000",
        "content_type": "21",
        "drm_type": "3",
        "min_fw": "3.60",
        "version": "1.00",
        "app_ver": "1.01",
        "size": "123456",
    }


def test_a_value_containing_a_colon_is_kept_whole(installed, monkeypatch):
    # Subtitled titles are commonplace, and splitting on every colon truncates
    # the name at the first one.
    info_command(monkeypatch, "Title: Ratchet & Clank: Up Your Arsenal")

    assert playstation.get_psn_package_info("/in/Game.pkg")["title"] == \
        "Ratchet & Clank: Up Your Arsenal"


def test_an_unknown_field_is_ignored(installed, monkeypatch):
    info_command(monkeypatch, "Something Else: value")

    assert playstation.get_psn_package_info("/in/Game.pkg") == {}


def test_a_line_without_a_field_is_ignored(installed, monkeypatch):
    info_command(monkeypatch, "just a banner line\nTitle: A Game")

    assert playstation.get_psn_package_info("/in/Game.pkg") == {"title": "A Game"}


def test_no_output_yields_nothing(installed, monkeypatch):
    info_command(monkeypatch, "")

    assert playstation.get_psn_package_info("/in/Game.pkg") is None


def test_package_info_without_the_tool_yields_nothing(missing, recording_command):
    assert playstation.get_psn_package_info("/in/Game.pkg") is None
    assert recording_command.ran() is False


###########################################################
# PSV stripping and trimming
###########################################################

def test_stripping_uses_the_strip_mode(installed, recording_command, existing_output):
    playstation.strip_psv("/in/Game.psv", "/out/Game.psv")

    assert recording_command.only() == \
        ["/tools/psvstrip", "-psvstrip", "/in/Game.psv", "/out/Game.psv"]


def test_unstripping_passes_the_side_file_last(installed, recording_command, existing_output):
    # -applypsve takes source, destination and then the .psve it reapplies.
    playstation.unstrip_psv("/in/Game.psv", "/in/Game.psve", "/out/Game.psv")

    assert recording_command.only() == \
        ["/tools/psvstrip", "-applypsve", "/in/Game.psv", "/out/Game.psv", "/in/Game.psve"]


def test_trimming_uses_the_trim_flag(installed, recording_command, existing_output):
    playstation.trim_psv("/in/Game.psv", "/out/Game.psv")

    assert "--trim" in recording_command.only()
    assert "--expand" not in recording_command.only()


def test_untrimming_uses_the_expand_flag(installed, recording_command, existing_output):
    playstation.untrim_psv("/in/Game.psv", "/out/Game.psv")

    assert "--expand" in recording_command.only()
    assert "--trim" not in recording_command.only()


@pytest.mark.parametrize("wrapper", [playstation.trim_psv, playstation.untrim_psv])
def test_the_output_file_is_named_with_o(installed, recording_command, existing_output, wrapper):
    wrapper("/in/Game.psv", "/out/Game.psv")

    assert recording_command.value_after("-o") == "/out/Game.psv"
    assert recording_command.only()[-1] == "/in/Game.psv"


def test_verifying_passes_only_the_image(installed, recording_command, existing_output):
    playstation.verify_psv("/in/Game.psv")

    assert recording_command.only() == \
        ["/tools/venv/python", "/tools/psvtools.py", "--verify", "/in/Game.psv"]


def test_a_verified_image_needs_no_output_file(installed, recording_command):
    # Verification writes nothing, so it must not be judged by a result file.
    assert playstation.verify_psv("/in/Game.psv") is True


@pytest.mark.parametrize("wrapper,args", [
    (playstation.strip_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.unstrip_psv, ("/in/Game.psv", "/in/Game.psve", "/out/Game.psv")),
    (playstation.trim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.untrim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.verify_psv, ("/in/Game.psv",)),
])
def test_a_psv_wrapper_without_its_tool_reports_failure(missing, recording_command, wrapper, args):
    assert wrapper(*args) is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper,args", [
    (playstation.strip_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.unstrip_psv, ("/in/Game.psv", "/in/Game.psve", "/out/Game.psv")),
    (playstation.trim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.untrim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.verify_psv, ("/in/Game.psv",)),
])
def test_a_failed_psv_wrapper_reports_failure(installed, monkeypatch, wrapper, args):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert wrapper(*args) is False


@pytest.mark.parametrize("wrapper,args", [
    (playstation.strip_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.unstrip_psv, ("/in/Game.psv", "/in/Game.psve", "/out/Game.psv")),
    (playstation.trim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.untrim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.verify_psv, ("/in/Game.psv",)),
])
def test_a_failed_psv_wrapper_can_quit_the_program(installed, monkeypatch, wrapper, args):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    with pytest.raises(SystemExit):
        wrapper(*args, exit_on_failure = True)


@pytest.mark.parametrize("wrapper,args", [
    (playstation.strip_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.trim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.untrim_psv, ("/in/Game.psv", "/out/Game.psv")),
])
def test_a_psv_wrapper_can_remove_the_source(installed, recording_command, existing_output, monkeypatch, wrapper, args):
    removed = []
    monkeypatch.setattr(playstation.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    wrapper(*args, delete_original = True)

    assert removed == ["/in/Game.psv"]


@pytest.mark.parametrize("wrapper,args", [
    (playstation.strip_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.trim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.untrim_psv, ("/in/Game.psv", "/out/Game.psv")),
])
def test_a_failed_psv_wrapper_keeps_the_source(installed, monkeypatch, wrapper, args):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    def fail(*args, **kwargs):
        raise AssertionError("the source must survive a failed conversion")

    monkeypatch.setattr(playstation.fileops, "remove_file", fail)

    assert wrapper(*args, delete_original = True) is False
