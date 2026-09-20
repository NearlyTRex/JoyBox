# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import nintendo


###########################################################
# Switch profiles
#
# The profile id and name come out of the user's ini and end up written into a
# binary profiles.dat at fixed offsets. The validator is what decides whether
# the emulator falls back to its defaults, so anything it accepts has to be
# writable.
###########################################################

VALID_ID = "F6F389D41D6BC0BDD6BD928C526AE556"


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

def read_dat(path):
    with open(str(path), "rb") as handle:
        return handle.read()


def test_a_profiles_dat_is_written(tmp_path):
    target = tmp_path / "profiles.dat"

    assert nintendo.create_switch_profiles_dat(str(target), VALID_ID, "yuzu") is True
    assert target.exists()


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
# Tool wrappers
#
# None of these tools are installed here, so what is pinned is the argument
# list each wrapper builds and what it does with the result. A mode token in
# the wrong place converts nothing and still returns zero.
###########################################################

TOOL_PATHS = {
    "NDecrypt": "/tools/ndecrypt",
    "CtrMakeRom": "/tools/makerom",
    "CtrTool": "/tools/ctrtool",
    "3DSRomTool": "/tools/3dsromtool",
    "CDecrypt": "/tools/cdecrypt",
    "HacTool": "/tools/hactool",
    "XCITrimmer": "/tools/xcitrimmer.py",
    "PythonVenvPython": "/tools/venv/python",
}


@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(nintendo.programs, "is_tool_installed", lambda name: name in TOOL_PATHS)
    monkeypatch.setattr(nintendo.programs, "get_tool_program", lambda name: TOOL_PATHS.get(name))
    return TOOL_PATHS


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(nintendo.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(nintendo.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def existing_output(monkeypatch):
    monkeypatch.setattr(nintendo.os.path, "exists", lambda path: True)


@pytest.fixture
def scratch(monkeypatch, tmp_path):
    # The wrappers stage their work in a temporary directory; handing them a
    # known one makes the intermediate names assertable.
    workspace = tmp_path / "scratch"
    workspace.mkdir()
    monkeypatch.setattr(
        nintendo.fileops, "create_temporary_directory",
        lambda **kwargs: (True, str(workspace)))
    return str(workspace)


@pytest.fixture
def no_scratch(monkeypatch):
    monkeypatch.setattr(
        nintendo.fileops, "create_temporary_directory",
        lambda **kwargs: (False, ""))


###########################################################
# Nintendo DS
###########################################################

def test_encrypting_a_ds_rom_uses_the_encrypt_mode(installed, recording_command):
    nintendo.encrypt_nds_rom("/in/Game.nds")

    assert recording_command.only() == ["/tools/ndecrypt", "e", "/in/Game.nds"]


def test_decrypting_a_ds_rom_uses_the_decrypt_mode(installed, recording_command):
    nintendo.decrypt_nds_rom("/in/Game.nds")

    assert recording_command.only() == ["/tools/ndecrypt", "d", "/in/Game.nds"]


@pytest.mark.parametrize("wrapper", [nintendo.encrypt_nds_rom, nintendo.decrypt_nds_rom])
def test_a_ds_hash_is_only_generated_when_asked(installed, recording_command, wrapper):
    wrapper("/in/Game.nds", generate_hash = True)

    assert "-h" in recording_command.only()


@pytest.mark.parametrize("wrapper", [nintendo.encrypt_nds_rom, nintendo.decrypt_nds_rom])
def test_the_rom_stays_last_after_the_hash_flag(installed, recording_command, wrapper):
    # NDecrypt takes the rom as a positional; a flag appended after it is read
    # as a second file.
    wrapper("/in/Game.nds", generate_hash = True)

    assert recording_command.only()[-1] == "/in/Game.nds"


@pytest.mark.parametrize("wrapper", [nintendo.encrypt_nds_rom, nintendo.decrypt_nds_rom])
def test_a_ds_wrapper_blocks_on_the_tool(installed, recording_command, wrapper):
    wrapper("/in/Game.nds")

    assert "/tools/ndecrypt" in recording_command.options().get_blocking_processes()


@pytest.mark.parametrize("wrapper", [nintendo.encrypt_nds_rom, nintendo.decrypt_nds_rom])
def test_a_ds_wrapper_without_its_tool_reports_failure(missing, recording_command, wrapper):
    assert wrapper("/in/Game.nds") is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper", [nintendo.encrypt_nds_rom, nintendo.decrypt_nds_rom])
def test_a_failed_ds_wrapper_reports_failure(installed, monkeypatch, wrapper):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert wrapper("/in/Game.nds") is False


###########################################################
# 3DS conversion
###########################################################

def test_converting_a_cia_to_a_cci_uses_its_own_mode(installed, recording_command, existing_output):
    nintendo.convert_3ds_cia_to_cci("/in/Game.cia", "/out/Game.cci")

    assert recording_command.only() == \
        ["/tools/makerom", "-ciatocci", "/in/Game.cia", "-o", "/out/Game.cci"]


def test_converting_a_cci_to_a_cia_uses_its_own_mode(installed, recording_command, existing_output):
    # The two modes differ by one token and swapping them writes a file the
    # emulator cannot read.
    nintendo.convert_3ds_cci_to_cia("/in/Game.cci", "/out/Game.cia")

    assert recording_command.only() == \
        ["/tools/makerom", "-ccitocia", "/in/Game.cci", "-o", "/out/Game.cia"]


@pytest.mark.parametrize("wrapper", [
    nintendo.convert_3ds_cia_to_cci,
    nintendo.convert_3ds_cci_to_cia,
])
def test_a_conversion_without_its_tool_reports_failure(missing, recording_command, wrapper):
    assert wrapper("/in/Game.cia", "/out/Game.cci") is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper", [
    nintendo.convert_3ds_cia_to_cci,
    nintendo.convert_3ds_cci_to_cia,
])
def test_a_failed_conversion_reports_failure(installed, monkeypatch, wrapper):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert wrapper("/in/Game.cia", "/out/Game.cci") is False


@pytest.mark.parametrize("wrapper", [
    nintendo.convert_3ds_cia_to_cci,
    nintendo.convert_3ds_cci_to_cia,
])
def test_a_conversion_that_writes_nothing_reports_failure(installed, recording_command, tmp_path, wrapper):
    # makerom can return zero and produce no file.
    assert wrapper("/in/Game.cia", str(tmp_path / "absent.cci")) is False


###########################################################
# 3DS trimming
###########################################################

def test_trimming_a_cci_uses_the_trim_flag(installed, recording_command, scratch, existing_output):
    nintendo.trim_3ds_cci("/in/Game.3ds", "/out/Game.3ds")

    assert recording_command.only() == \
        ["/tools/3dsromtool", "--trim", os.path.join(scratch, "temp.3ds")]


def test_untrimming_a_cci_uses_the_restore_flag(installed, recording_command, scratch, existing_output):
    nintendo.untrim_3ds_cci("/in/Game.3ds", "/out/Game.3ds")

    assert recording_command.only() == \
        ["/tools/3dsromtool", "--restore", os.path.join(scratch, "temp.3ds")]


@pytest.mark.parametrize("wrapper", [nintendo.trim_3ds_cci, nintendo.untrim_3ds_cci])
def test_trimming_works_on_a_copy(installed, recording_command, scratch, existing_output, monkeypatch, wrapper):
    # The tool edits its input in place, so the original must not be handed to
    # it directly.
    copies = []
    monkeypatch.setattr(
        nintendo.fileops, "copy_file_or_directory",
        lambda src, dest, **kwargs: copies.append((src, dest)))

    wrapper("/in/Game.3ds", "/out/Game.3ds")

    assert copies == [("/in/Game.3ds", os.path.join(scratch, "temp.3ds"))]


@pytest.mark.parametrize("wrapper", [nintendo.trim_3ds_cci, nintendo.untrim_3ds_cci])
def test_the_trimmed_copy_is_moved_to_the_destination(installed, recording_command, scratch, existing_output, monkeypatch, wrapper):
    moves = []
    monkeypatch.setattr(
        nintendo.fileops, "move_file_or_directory",
        lambda src, dest, **kwargs: moves.append((src, dest)))

    wrapper("/in/Game.3ds", "/out/Game.3ds")

    assert moves == [(os.path.join(scratch, "temp.3ds"), "/out/Game.3ds")]


@pytest.mark.parametrize("wrapper", [nintendo.trim_3ds_cci, nintendo.untrim_3ds_cci])
def test_trimming_without_its_tool_reports_failure(missing, recording_command, wrapper):
    assert wrapper("/in/Game.3ds", "/out/Game.3ds") is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper", [nintendo.trim_3ds_cci, nintendo.untrim_3ds_cci])
def test_trimming_without_a_scratch_directory_reports_failure(installed, recording_command, no_scratch, wrapper):
    assert wrapper("/in/Game.3ds", "/out/Game.3ds") is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper", [nintendo.trim_3ds_cci, nintendo.untrim_3ds_cci])
def test_a_failed_trim_does_not_move_anything(installed, monkeypatch, scratch, wrapper):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    def fail(*args, **kwargs):
        raise AssertionError("a failed trim must not overwrite the destination")

    monkeypatch.setattr(nintendo.fileops, "move_file_or_directory", fail)

    assert wrapper("/in/Game.3ds", "/out/Game.3ds") is False


###########################################################
# 3DS extraction
###########################################################

def test_extracting_a_cia_names_every_output(installed, recording_command, scratch, existing_output, monkeypatch):
    monkeypatch.setattr(nintendo.paths, "get_directory_contents", lambda path: [])
    monkeypatch.setattr(nintendo.paths, "is_directory_empty", lambda path: False)
    monkeypatch.setattr(nintendo.fileops, "move_contents", lambda **kwargs: True)

    nintendo.extract_3ds_cia("/in/Game.cia", "/out")
    cmd = recording_command.only()

    assert cmd[0] == "/tools/ctrtool"
    assert recording_command.value_after("--certs") == os.path.join(scratch, "00000000.cer")
    assert recording_command.value_after("--tik") == os.path.join(scratch, "00000000.tik")
    assert recording_command.value_after("--tmd") == os.path.join(scratch, "00000000.tmd")
    assert cmd[-1] == "/in/Game.cia"


def test_extracted_contents_are_renamed_to_app_files(installed, recording_command, scratch, existing_output, monkeypatch):
    # ctrtool writes contents.0000, and the emulator expects 0000.app.
    moves = []
    monkeypatch.setattr(nintendo.paths, "get_directory_contents", lambda path: ["contents.0000", "00000000.tik"])
    monkeypatch.setattr(nintendo.paths, "is_directory_empty", lambda path: False)
    monkeypatch.setattr(nintendo.fileops, "move_contents", lambda **kwargs: True)
    monkeypatch.setattr(
        nintendo.fileops, "move_file_or_directory",
        lambda src, dest, **kwargs: moves.append((src, dest)))

    nintendo.extract_3ds_cia("/in/Game.cia", "/out")

    assert moves == [(os.path.join(scratch, "contents.0000"), os.path.join(scratch, "0000.app"))]


def test_extracting_a_cia_without_its_tool_reports_failure(missing, recording_command):
    assert nintendo.extract_3ds_cia("/in/Game.cia", "/out") is False
    assert recording_command.ran() is False


def test_a_failed_cia_extract_reports_failure(installed, monkeypatch, scratch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert nintendo.extract_3ds_cia("/in/Game.cia", "/out") is False


def test_an_empty_extraction_reports_failure(installed, recording_command, scratch, existing_output, monkeypatch):
    # A run that produced an empty directory is not an extraction.
    monkeypatch.setattr(nintendo.paths, "get_directory_contents", lambda path: [])
    monkeypatch.setattr(nintendo.paths, "is_directory_empty", lambda path: True)
    monkeypatch.setattr(nintendo.fileops, "move_contents", lambda **kwargs: True)

    assert nintendo.extract_3ds_cia("/in/Game.cia", "/out") is False


###########################################################
# 3DS information and installation
###########################################################

def test_file_info_is_returned_as_the_tool_printed_it(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = "Title id:          0004000000123400")

    assert nintendo.get_3ds_file_info("/in/Game.cia") == "Title id:          0004000000123400"


def test_file_info_without_its_tool_is_empty(missing, recording_command):
    assert nintendo.get_3ds_file_info("/in/Game.cia") == ""
    assert recording_command.ran() is False


def test_installing_a_cia_uses_the_title_id_for_its_path(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = "Title id:          0004000000123400")
    seen = {}

    def extract_3ds_cia(src_3ds_file, extract_dir, **kwargs):
        seen["dir"] = extract_dir
        return True

    monkeypatch.setattr(nintendo, "extract_3ds_cia", extract_3ds_cia)

    assert nintendo.install_3ds_cia("/in/Game.cia", "/sdmc") is True
    assert seen["dir"].endswith(os.path.join("title", "00040000", "00123400", "content"))


def test_installing_a_cia_lowercases_the_title_id(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = "Title id:          000400000012AB00")
    seen = {}

    def extract_3ds_cia(src_3ds_file, extract_dir, **kwargs):
        seen["dir"] = extract_dir
        return True

    monkeypatch.setattr(nintendo, "extract_3ds_cia", extract_3ds_cia)
    nintendo.install_3ds_cia("/in/Game.cia", "/sdmc")

    assert seen["dir"].endswith(os.path.join("00040000", "0012ab00", "content"))


@pytest.mark.parametrize("output", [
    "",
    "Title id:          00040000",
    "no fields at all",
])
def test_a_cia_without_a_usable_title_id_is_not_installed(installed, monkeypatch, output):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = output)

    def fail(*args, **kwargs):
        raise AssertionError("nothing may be extracted without a title id")

    monkeypatch.setattr(nintendo, "extract_3ds_cia", fail)

    assert nintendo.install_3ds_cia("/in/Game.cia", "/sdmc") is False


def test_a_cia_that_will_not_extract_is_not_installed(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = "Title id:          0004000000123400")
    monkeypatch.setattr(nintendo, "extract_3ds_cia", lambda **kwargs: False)

    assert nintendo.install_3ds_cia("/in/Game.cia", "/sdmc") is False


###########################################################
# Wii U packages
###########################################################

@pytest.fixture
def nus_package(tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    (package / "title.tmd").write_bytes(b"tmd")
    (package / "title.tik").write_bytes(b"tik")
    (package / "title.cert").write_bytes(b"cert")
    (package / "00000000.app").write_bytes(b"app")
    (package / "keep.txt").write_text("notes")
    return str(package)


def test_decrypting_a_package_passes_its_title_files(installed, recording_command, nus_package):
    nintendo.decrypt_wiiu_nus_package(nus_package)

    assert recording_command.only() == [
        "/tools/cdecrypt",
        os.path.join(nus_package, "title.tmd"),
        os.path.join(nus_package, "title.tik"),
    ]


def test_decrypting_a_package_runs_inside_it(installed, recording_command, nus_package):
    # CDecrypt writes its output into the working directory.
    nintendo.decrypt_wiiu_nus_package(nus_package)

    assert recording_command.options().get_cwd() == nus_package


@pytest.mark.parametrize("absent", ["title.tmd", "title.tik"])
def test_a_package_missing_a_title_file_is_not_decrypted(installed, recording_command, nus_package, absent):
    os.remove(os.path.join(nus_package, absent))

    assert nintendo.decrypt_wiiu_nus_package(nus_package) is False
    assert recording_command.ran() is False


def test_decrypting_a_package_without_its_tool_reports_failure(missing, recording_command, nus_package):
    assert nintendo.decrypt_wiiu_nus_package(nus_package) is False
    assert recording_command.ran() is False


def test_a_failed_package_decrypt_reports_failure(installed, monkeypatch, nus_package):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert nintendo.decrypt_wiiu_nus_package(nus_package) is False


def test_decrypting_removes_only_the_encrypted_sources(installed, recording_command, nus_package):
    # The decrypted output shares the directory, so the cleanup is by
    # extension and must leave anything else alone.
    assert nintendo.decrypt_wiiu_nus_package(nus_package, delete_original = True) is True
    assert sorted(os.listdir(nus_package)) == ["keep.txt"]


def test_a_failed_decrypt_removes_nothing(installed, monkeypatch, nus_package):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    nintendo.decrypt_wiiu_nus_package(nus_package, delete_original = True)

    assert "title.tmd" in os.listdir(nus_package)


def test_verifying_a_package_works_on_a_copy(installed, recording_command, nus_package, scratch, monkeypatch):
    # Decryption writes into the package directory, so verifying in place
    # would modify the very thing it was asked to check.
    seen = {}
    monkeypatch.setattr(nintendo.fileops, "copy_contents", lambda src, dest, **kwargs: True)
    def decrypt_wiiu_nus_package(nus_package_dir, **kwargs):
        seen["dir"] = nus_package_dir
        return True

    monkeypatch.setattr(nintendo, "decrypt_wiiu_nus_package", decrypt_wiiu_nus_package)

    nintendo.verify_wiiu_nus_package(nus_package)

    assert seen["dir"] == scratch


def test_verifying_a_package_copies_it_to_the_scratch_directory(installed, recording_command, nus_package, scratch, monkeypatch):
    copies = []
    monkeypatch.setattr(
        nintendo.fileops, "copy_contents",
        lambda src, dest, **kwargs: copies.append((src, dest)))
    monkeypatch.setattr(nintendo, "decrypt_wiiu_nus_package", lambda **kwargs: True)

    nintendo.verify_wiiu_nus_package(nus_package)

    assert copies == [(nus_package, scratch)]


def test_a_package_that_will_not_decrypt_is_not_verified(installed, nus_package, scratch, monkeypatch):
    monkeypatch.setattr(nintendo.fileops, "copy_contents", lambda **kwargs: True)
    monkeypatch.setattr(nintendo, "decrypt_wiiu_nus_package", lambda **kwargs: False)

    assert nintendo.verify_wiiu_nus_package(nus_package) is False


def test_verifying_without_a_scratch_directory_reports_failure(installed, nus_package, no_scratch):
    assert nintendo.verify_wiiu_nus_package(nus_package) is False


###########################################################
# Wii U keys
###########################################################

def test_new_keys_are_added_to_the_existing_ones(tmp_path):
    existing = tmp_path / "keys.txt"
    existing.write_text("aaa\nbbb\n")
    incoming = tmp_path / "new.txt"
    incoming.write_text("ccc\n")

    nintendo.update_wiiu_keys(str(incoming), str(existing))

    assert existing.read_text().split() == ["aaa", "bbb", "ccc"]


def test_a_key_already_present_is_not_duplicated(tmp_path):
    existing = tmp_path / "keys.txt"
    existing.write_text("aaa\nbbb\n")
    incoming = tmp_path / "new.txt"
    incoming.write_text("bbb\nccc\n")

    nintendo.update_wiiu_keys(str(incoming), str(existing))

    assert existing.read_text().split() == ["aaa", "bbb", "ccc"]


def test_keys_are_written_in_a_stable_order(tmp_path):
    # An unsorted rewrite makes every update look like a change in git.
    existing = tmp_path / "keys.txt"
    existing.write_text("ccc\naaa\n")
    incoming = tmp_path / "new.txt"
    incoming.write_text("bbb\n")

    nintendo.update_wiiu_keys(str(incoming), str(existing))

    assert existing.read_text().split() == ["aaa", "bbb", "ccc"]


def test_surrounding_whitespace_is_stripped_from_keys(tmp_path):
    existing = tmp_path / "keys.txt"
    existing.write_text("  aaa  \n")
    incoming = tmp_path / "new.txt"
    incoming.write_text("\taaa\n")

    nintendo.update_wiiu_keys(str(incoming), str(existing))

    assert existing.read_text().split() == ["aaa"]


def test_the_source_key_file_is_left_alone(tmp_path):
    existing = tmp_path / "keys.txt"
    existing.write_text("aaa\n")
    incoming = tmp_path / "new.txt"
    incoming.write_text("bbb\n")

    nintendo.update_wiiu_keys(str(incoming), str(existing))

    assert incoming.read_text() == "bbb\n"


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
