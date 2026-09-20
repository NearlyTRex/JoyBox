# Imports
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
