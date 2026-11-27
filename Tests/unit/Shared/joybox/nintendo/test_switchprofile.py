# Imports
import pytest

# Local imports
from joybox.nintendo import switchprofile
from nintendo_helpers import VALID_ID


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
    assert switchprofile.is_valid_switch_profile_info(VALID_ID, "yuzu") is True


def test_a_lowercase_id_is_accepted():
    assert switchprofile.is_valid_switch_profile_info(VALID_ID.lower(), "yuzu") is True


def test_an_all_digit_id_is_accepted():
    assert switchprofile.is_valid_switch_profile_info("0" * 32, "yuzu") is True


@pytest.mark.parametrize("user_id", [
    VALID_ID[:31],
    VALID_ID + "0",
    "",
    None,
    12345,
    ["a" * 32],
])
def test_an_id_of_the_wrong_shape_is_refused(user_id):
    assert switchprofile.is_valid_switch_profile_info(user_id, "yuzu") is False


@pytest.mark.parametrize("user_id", [
    "z" * 32,
    "F6F389D41D6BC0BDD6BD928C526AE55G",
    "my switch profile name here 1234",
    "-" * 32,
])
def test_a_non_hexadecimal_id_is_refused(user_id):
    # The id is converted with fromhex, which raises rather than returning
    # anything, so a typed-in name of the right length used to crash setup.
    assert switchprofile.is_valid_switch_profile_info(user_id, "yuzu") is False


def test_a_long_account_name_is_refused():
    assert switchprofile.is_valid_switch_profile_info(VALID_ID, "n" * 33) is False


def test_an_account_name_at_the_limit_is_accepted():
    assert switchprofile.is_valid_switch_profile_info(VALID_ID, "n" * 32) is True


@pytest.mark.parametrize("account_name", ["", None, 12345, ["yuzu"]])
def test_an_unusable_account_name_is_refused(account_name):
    # Anything the validator accepts must be writable; an empty name is not.
    assert switchprofile.is_valid_switch_profile_info(VALID_ID, account_name) is False
