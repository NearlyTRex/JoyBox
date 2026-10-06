# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import nintendo
from nintendo_helpers import VALID_ID, read_dat


###########################################################
# Switch profiles
#
# The profile id and name come out of the user's ini and end up written into a
# binary profiles.dat at fixed offsets. The validator is what decides whether
# the emulator falls back to its defaults, so anything it accepts has to be
# writable.
###########################################################

###########################################################
# Validation
###########################################################

def test_a_valid_profile_is_accepted():
    assert nintendo.is_valid_switch_profile_info(VALID_ID, "yuzu") is True


def test_a_lowercase_id_is_accepted():
    assert nintendo.is_valid_switch_profile_info(VALID_ID.lower(), "yuzu") is True


def test_an_all_digit_id_is_accepted():
    assert nintendo.is_valid_switch_profile_info("0" * 32, "yuzu") is True


@pytest.mark.parametrize("user_id", [
    VALID_ID[:31],
    VALID_ID + "0",
    "",
    None,
    12345,
    ["a" * 32],
])
def test_an_id_of_the_wrong_shape_is_refused(user_id):
    assert nintendo.is_valid_switch_profile_info(user_id, "yuzu") is False


@pytest.mark.parametrize("user_id", [
    "z" * 32,
    "F6F389D41D6BC0BDD6BD928C526AE55G",
    "my switch profile name here 1234",
    "-" * 32,
])
def test_a_non_hexadecimal_id_is_refused(user_id):
    # The id is converted with fromhex, which raises rather than returning
    # anything, so a typed-in name of the right length used to crash setup.
    assert nintendo.is_valid_switch_profile_info(user_id, "yuzu") is False


def test_a_long_account_name_is_refused():
    assert nintendo.is_valid_switch_profile_info(VALID_ID, "n" * 33) is False


def test_an_account_name_at_the_limit_is_accepted():
    assert nintendo.is_valid_switch_profile_info(VALID_ID, "n" * 32) is True


@pytest.mark.parametrize("account_name", ["", None, 12345, ["yuzu"]])
def test_an_unusable_account_name_is_refused(account_name):
    # Anything the validator accepts must be writable; an empty name is not.
    assert nintendo.is_valid_switch_profile_info(VALID_ID, account_name) is False


###########################################################
# Writing profiles.dat
###########################################################

def test_a_profiles_dat_is_written(tmp_path):
    target = tmp_path / "profiles.dat"

    assert nintendo.create_switch_profiles_dat(str(target), VALID_ID, "yuzu") is True
    assert target.exists()


def test_a_pretend_profiles_dat_succeeds_without_writing(tmp_path):
    target = tmp_path / "profiles.dat"

    assert nintendo.create_switch_profiles_dat(str(target), VALID_ID, "yuzu", pretend_run = True) is True
    assert not target.exists()


def test_a_profiles_dat_is_the_expected_size(tmp_path):
    # The emulator reads a fixed size record; a short file is not loadable.
    target = tmp_path / "profiles.dat"
    nintendo.create_switch_profiles_dat(str(target), VALID_ID, "yuzu")

    assert len(read_dat(target)) == 1616


def test_the_user_id_is_written_byte_reversed(tmp_path):
    # The id is stored little endian, so it is not the hex string as typed.
    target = tmp_path / "profiles.dat"
    nintendo.create_switch_profiles_dat(str(target), VALID_ID, "yuzu")

    expected = bytes(reversed(bytes.fromhex(VALID_ID)))
    assert read_dat(target)[0x10:0x20] == expected


def test_the_user_id_is_written_twice(tmp_path):
    target = tmp_path / "profiles.dat"
    nintendo.create_switch_profiles_dat(str(target), VALID_ID, "yuzu")
    data = read_dat(target)

    assert data[0x10:0x20] == data[0x20:0x30]


def test_the_account_name_is_written_at_its_offset(tmp_path):
    target = tmp_path / "profiles.dat"
    nintendo.create_switch_profiles_dat(str(target), VALID_ID, "yuzu")

    assert read_dat(target)[0x38:0x3C] == b"yuzu"


def test_the_account_name_is_null_terminated(tmp_path):
    target = tmp_path / "profiles.dat"
    nintendo.create_switch_profiles_dat(str(target), VALID_ID, "yuzu")

    assert read_dat(target)[0x3C] == 0


def test_a_longer_account_name_is_written_whole(tmp_path):
    target = tmp_path / "profiles.dat"
    name = "a" * 32
    nintendo.create_switch_profiles_dat(str(target), VALID_ID, name)

    assert read_dat(target)[0x38:0x38 + 32] == name.encode("utf-8")


def test_a_unicode_account_name_is_written_as_utf8(tmp_path):
    target = tmp_path / "profiles.dat"
    nintendo.create_switch_profiles_dat(str(target), VALID_ID, "ドラ")

    assert read_dat(target)[0x38:0x3E] == "ドラ".encode("utf-8")


def test_the_rest_of_the_record_is_blank(tmp_path):
    target = tmp_path / "profiles.dat"
    nintendo.create_switch_profiles_dat(str(target), VALID_ID, "yuzu")
    data = read_dat(target)

    assert data[:0x10] == b"\x00" * 0x10
    assert data[0x30:0x38] == b"\x00" * 8
    assert data[0x100:] == b"\x00" * (1616 - 0x100)


def test_two_profiles_differ_by_their_id(tmp_path):
    first = tmp_path / "first.dat"
    second = tmp_path / "second.dat"
    nintendo.create_switch_profiles_dat(str(first), VALID_ID, "yuzu")
    nintendo.create_switch_profiles_dat(str(second), "0" * 32, "yuzu")

    assert read_dat(first) != read_dat(second)


###########################################################
# Refused profiles
###########################################################

@pytest.mark.parametrize("user_id,account_name", [
    ("z" * 32, "yuzu"),
    (VALID_ID[:31], "yuzu"),
    (VALID_ID, ""),
    (VALID_ID, "n" * 33),
    (None, "yuzu"),
    (VALID_ID, None),
])
def test_an_invalid_profile_writes_nothing(tmp_path, user_id, account_name):
    target = tmp_path / "profiles.dat"

    assert nintendo.create_switch_profiles_dat(
        str(target), user_id, account_name) is False
    assert not target.exists()


def test_pretending_writes_nothing(tmp_path):
    target = tmp_path / "profiles.dat"
    nintendo.create_switch_profiles_dat(
        str(target), VALID_ID, "yuzu", pretend_run = True)

    assert not target.exists()


###########################################################
# Switch images
###########################################################

def test_trimming_an_xci_uses_the_trim_flag(installed, recording_command, scratch, existing_output):
    nintendo.trim_switch_xci("/in/Game.xci", "/out/Game.xci")

    assert recording_command.only() == [
        "/tools/venv/python",
        "/tools/xcitrimmer.py",
        "--trim",
        "--copy",
        os.path.join(scratch, "Game.xci"),
    ]


def test_untrimming_an_xci_uses_the_pad_flag(installed, recording_command, scratch, existing_output):
    nintendo.untrim_switch_xci("/in/Game.xci", "/out/Game.xci")

    assert recording_command.only() == [
        "/tools/venv/python",
        "/tools/xcitrimmer.py",
        "--pad",
        "--copy",
        os.path.join(scratch, "Game.xci"),
    ]


@pytest.mark.parametrize("wrapper,produced", [
    (nintendo.trim_switch_xci, "Game_trimmed.xci"),
    (nintendo.untrim_switch_xci, "Game_padded.xci"),
])
def test_the_tools_own_output_name_is_collected(installed, recording_command, scratch, existing_output, monkeypatch, wrapper, produced):
    # XCITrimmer names its result itself, and moving the wrong name leaves the
    # destination empty while still reporting success.
    moves = []
    monkeypatch.setattr(
        nintendo.fileops, "move_file_or_directory",
        lambda src, dest, **kwargs: moves.append((src, dest)))

    wrapper("/in/Game.xci", "/out/Game.xci")

    assert moves == [(os.path.join(scratch, produced), "/out/Game.xci")]


@pytest.mark.parametrize("wrapper", [nintendo.trim_switch_xci, nintendo.untrim_switch_xci])
def test_an_xci_wrapper_works_on_a_copy(installed, recording_command, scratch, existing_output, monkeypatch, wrapper):
    copies = []
    monkeypatch.setattr(
        nintendo.fileops, "copy_file_or_directory",
        lambda src, dest, **kwargs: copies.append((src, dest)))

    wrapper("/in/Game.xci", "/out/Game.xci")

    assert copies == [("/in/Game.xci", os.path.join(scratch, "Game.xci"))]


@pytest.mark.parametrize("wrapper", [nintendo.trim_switch_xci, nintendo.untrim_switch_xci])
def test_an_xci_wrapper_can_remove_the_source(installed, recording_command, scratch, existing_output, monkeypatch, wrapper):
    removed = []
    monkeypatch.setattr(nintendo.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    wrapper("/in/Game.xci", "/out/Game.xci", delete_original = True)

    assert removed == ["/in/Game.xci"]


@pytest.mark.parametrize("wrapper", [nintendo.trim_switch_xci, nintendo.untrim_switch_xci])
def test_a_failed_xci_wrapper_keeps_the_source(installed, monkeypatch, scratch, wrapper):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    def fail(*args, **kwargs):
        raise AssertionError("the source must survive a failed conversion")

    monkeypatch.setattr(nintendo.fileops, "remove_file", fail)

    assert wrapper("/in/Game.xci", "/out/Game.xci", delete_original = True) is False


@pytest.mark.parametrize("wrapper", [nintendo.trim_switch_xci, nintendo.untrim_switch_xci])
def test_an_xci_wrapper_without_its_tool_reports_failure(missing, recording_command, wrapper):
    assert wrapper("/in/Game.xci", "/out/Game.xci") is False
    assert recording_command.ran() is False


###########################################################
# Switch packages
###########################################################

def test_extracting_an_nsp_names_its_container_type(installed, recording_command, existing_output, monkeypatch):
    # hactool reads any container; the wrong type flag extracts nothing.
    monkeypatch.setattr(nintendo.paths, "is_directory_empty", lambda path: False)

    nintendo.extract_switch_nsp("/in/Game.nsp", "/out")

    assert recording_command.value_after("-t") == "pfs0"
    assert recording_command.value_after("--outdir") == "/out"
    assert recording_command.only()[-1] == "/in/Game.nsp"


def test_extracting_an_nsp_without_its_tool_reports_failure(missing, recording_command):
    assert nintendo.extract_switch_nsp("/in/Game.nsp", "/out") is False
    assert recording_command.ran() is False


def test_a_failed_nsp_extract_reports_failure(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert nintendo.extract_switch_nsp("/in/Game.nsp", "/out") is False


def test_an_empty_nsp_extract_reports_failure(installed, recording_command, existing_output, monkeypatch):
    monkeypatch.setattr(nintendo.paths, "is_directory_empty", lambda path: True)

    assert nintendo.extract_switch_nsp("/in/Game.nsp", "/out") is False


def test_installing_an_nsp_files_each_nca_by_its_hash(installed, scratch, monkeypatch, tmp_path):
    # The registered directory is named from the first byte of the sha256 of
    # the nca id, so a wrong digest hides the title from the emulator.
    nca_id = "00112233445566778899aabbccddeeff"
    nca_file = os.path.join(scratch, nca_id + ".nca")
    with open(nca_file, "wb") as handle:
        handle.write(b"nca")

    copies = []
    monkeypatch.setattr(nintendo, "extract_switch_nsp", lambda **kwargs: True)
    monkeypatch.setattr(nintendo.fileops, "make_directory", lambda **kwargs: True)
    monkeypatch.setattr(
        nintendo.fileops, "copy_file_or_directory",
        lambda src, dest, **kwargs: copies.append((src, dest)) or True)

    assert nintendo.install_switch_nsp("/in/Game.nsp", "/nand") is True

    expected_digest = nintendo.hashing.calculate_string_sha256(bytes.fromhex(nca_id)).upper()
    assert copies[0][1] == os.path.join(
        "/nand", "user", "Contents", "registered",
        "000000%s" % expected_digest[0:2], nca_id + ".nca")


def test_an_nsp_that_will_not_extract_is_not_installed(installed, scratch, monkeypatch):
    # An empty scratch directory after a failed extract used to look like a
    # package with no content, and the install reported success.
    monkeypatch.setattr(nintendo, "extract_switch_nsp", lambda **kwargs: False)

    assert nintendo.install_switch_nsp("/in/Game.nsp", "/nand") is False


def test_installing_an_nsp_without_a_scratch_directory_reports_failure(installed, no_scratch):
    assert nintendo.install_switch_nsp("/in/Game.nsp", "/nand") is False


def test_a_cnmt_nca_is_filed_by_its_bare_id(installed, scratch, monkeypatch):
    nca_id = "00112233445566778899aabbccddeeff"
    with open(os.path.join(scratch, nca_id + ".cnmt.nca"), "wb") as handle:
        handle.write(b"cnmt")
    copies = []
    monkeypatch.setattr(nintendo, "extract_switch_nsp", lambda **kwargs: True)
    monkeypatch.setattr(nintendo.fileops, "make_directory", lambda **kwargs: True)
    monkeypatch.setattr(
        nintendo.fileops, "copy_file_or_directory",
        lambda src, dest, **kwargs: copies.append(dest) or True)

    assert nintendo.install_switch_nsp("/in/Game.nsp", "/nand") is True
    assert os.path.basename(copies[0]) == nca_id + ".nca"


@pytest.mark.parametrize("failing", ["make_directory", "copy_file_or_directory"])
def test_an_nca_that_cannot_be_filed_stops_the_install(installed, scratch, monkeypatch, failing):
    with open(os.path.join(scratch, "00112233445566778899aabbccddeeff.nca"), "wb") as handle:
        handle.write(b"nca")
    monkeypatch.setattr(nintendo, "extract_switch_nsp", lambda **kwargs: True)
    monkeypatch.setattr(nintendo.fileops, "make_directory", lambda **kwargs: True)
    monkeypatch.setattr(nintendo.fileops, "copy_file_or_directory", lambda **kwargs: True)
    monkeypatch.setattr(nintendo.fileops, failing, lambda **kwargs: False)

    assert nintendo.install_switch_nsp("/in/Game.nsp", "/nand") is False


@pytest.mark.parametrize("wrapper", [nintendo.trim_switch_xci, nintendo.untrim_switch_xci])
def test_an_xci_wrapper_without_its_script_reports_failure(installed, recording_command, wrapper):
    del installed["XCITrimmer"]

    assert wrapper("/in/Game.xci", "/out/Game.xci") is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper", [nintendo.trim_switch_xci, nintendo.untrim_switch_xci])
def test_an_xci_wrapper_without_a_scratch_directory_reports_failure(installed, recording_command, no_scratch, wrapper):
    assert wrapper("/in/Game.xci", "/out/Game.xci") is False
    assert recording_command.ran() is False


def test_a_profiles_dat_that_cannot_be_written_reports_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(nintendo.fileops, "touch_file", lambda **kwargs: False)

    assert nintendo.create_switch_profiles_dat(str(tmp_path / "profiles.dat"), VALID_ID, "yuzu") is False
