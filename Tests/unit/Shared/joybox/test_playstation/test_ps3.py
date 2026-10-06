# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import playstation
from playstation_helpers import FAKE_DISC_KEY


###########################################################
# PS3 decryption keys
###########################################################

def test_a_decryption_key_is_read(tmp_path):
    target = tmp_path / "game.dkey"
    target.write_text(FAKE_DISC_KEY)

    assert playstation.get_ps3_decryption_key(str(target)) == \
        FAKE_DISC_KEY


def test_a_decryption_key_is_stripped(tmp_path):
    # Redump dkey files carry a trailing newline, which ps3dec rejects.
    target = tmp_path / "game.dkey"
    target.write_text("  %s \n" % FAKE_DISC_KEY)

    assert playstation.get_ps3_decryption_key(str(target)) == \
        FAKE_DISC_KEY


def test_a_missing_key_file_reads_as_empty(tmp_path):
    assert playstation.get_ps3_decryption_key(str(tmp_path / "absent.dkey")) == ""


def test_an_empty_key_file_reads_as_empty(tmp_path):
    target = tmp_path / "game.dkey"
    target.write_text("\n")

    assert playstation.get_ps3_decryption_key(str(target)) == ""


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

    assert recording_command.value_after("key") == FAKE_DISC_KEY


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


def test_a_wrong_eboot_header_can_quit_the_program(decrypted, extracted, key_file, monkeypatch):
    monkeypatch.setattr(playstation.fileops, "is_file_correctly_headered", lambda src, header: header != "SCE")

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


def test_a_chd_is_not_verified_without_a_scratch_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(playstation.fileops, "create_temporary_directory", lambda **kwargs: (False, ""))

    def fail(*args, **kwargs):
        raise AssertionError("nothing may be extracted without a scratch directory")

    monkeypatch.setattr(playstation.chd, "extract_disc_chd", fail)

    assert playstation.verify_ps3_chd(str(tmp_path / "Game.chd")) is False


@pytest.mark.parametrize("chd_extracts", [True, False])
def test_verifying_a_chd_removes_its_scratch_directory(installed, monkeypatch, tmp_path, chd_extracts):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(playstation.fileops, "create_temporary_directory", lambda **kwargs: (True, str(scratch)))
    monkeypatch.setattr(playstation.chd, "extract_disc_chd", lambda **kwargs: chd_extracts)
    monkeypatch.setattr(playstation, "extract_ps3_iso", lambda **kwargs: False)

    assert playstation.verify_ps3_chd(str(tmp_path / "Game.chd")) is False
    assert not scratch.exists()
