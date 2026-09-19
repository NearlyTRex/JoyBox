# Imports
import pytest

# Local imports
from joybox import validation


###########################################################
# Assertions
#
# These guard entry points across the tree, so each has to reject what it
# names and accept nothing wider.
###########################################################

def assert_passes(check, *args):
    check(*args)


def assert_rejects(check, *args):
    with pytest.raises(AssertionError):
        check(*args)


###########################################################
# Conditions and presence
###########################################################

def test_a_true_condition_passes():
    assert_passes(validation.assert_condition, True, "description")


def test_a_false_condition_is_rejected():
    assert_rejects(validation.assert_condition, False, "description")


def test_the_description_reaches_the_message():
    with pytest.raises(AssertionError, match = "something useful"):
        validation.assert_condition(False, "something useful")


def test_a_value_that_is_not_none_passes():
    assert_passes(validation.assert_is_not_none, 0, "value")
    assert_passes(validation.assert_is_not_none, "", "value")


def test_none_is_rejected():
    assert_rejects(validation.assert_is_not_none, None, "value")


###########################################################
# Strings
###########################################################

@pytest.mark.parametrize("value", ["text", ""])
def test_a_string_passes(value):
    assert_passes(validation.assert_is_string, value, "value")


@pytest.mark.parametrize("value", [None, 1, b"bytes", ["text"]])
def test_a_non_string_is_rejected(value):
    assert_rejects(validation.assert_is_string, value, "value")


def test_a_non_empty_string_passes():
    assert_passes(validation.assert_is_non_empty_string, "text", "value")


@pytest.mark.parametrize("value", ["", None, 1])
def test_an_empty_or_non_string_is_rejected(value):
    assert_rejects(validation.assert_is_non_empty_string, value, "value")


def test_a_string_of_the_right_length_passes():
    assert_passes(validation.assert_is_string_of_specific_length, "abc", 3, "value")


@pytest.mark.parametrize("value", ["ab", "abcd", ""])
def test_a_string_of_the_wrong_length_is_rejected(value):
    assert_rejects(validation.assert_is_string_of_specific_length, value, 3, "value")


###########################################################
# Numbers
###########################################################

def test_an_int_passes():
    assert_passes(validation.assert_is_int, 1, "value")


@pytest.mark.parametrize("value", ["1", 1.5, True, None])
def test_a_non_int_is_rejected(value):
    # bool is a subclass of int, but type() is compared exactly.
    assert_rejects(validation.assert_is_int, value, "value")


@pytest.mark.parametrize("value", [1, "1", 1.5, "-3"])
def test_a_castable_int_passes(value):
    assert_passes(validation.assert_is_castable_to_int, value, "value")


@pytest.mark.parametrize("value", ["text", None, []])
def test_an_uncastable_int_is_rejected(value):
    assert_rejects(validation.assert_is_castable_to_int, value, "value")


###########################################################
# Booleans
###########################################################

@pytest.mark.parametrize("value", [True, False])
def test_a_bool_passes(value):
    assert_passes(validation.assert_is_bool, value, "value")


@pytest.mark.parametrize("value", ["True", 1, None])
def test_a_non_bool_is_rejected(value):
    assert_rejects(validation.assert_is_bool, value, "value")


@pytest.mark.parametrize("value", [True, False, "True", "False", "true", "yes", "no", "1", "0", "on", "off"])
def test_a_castable_bool_passes(value):
    # An actual bool has to pass the castable check, as an int does for ints.
    assert_passes(validation.assert_is_castable_to_bool, value, "value")


@pytest.mark.parametrize("value", [None, "maybe", []])
def test_an_uncastable_bool_is_rejected(value):
    assert_rejects(validation.assert_is_castable_to_bool, value, "value")


###########################################################
# Containers
###########################################################

def test_a_list_passes():
    assert_passes(validation.assert_is_list, [], "value")


@pytest.mark.parametrize("value", [(), {}, "text", None])
def test_a_non_list_is_rejected(value):
    assert_rejects(validation.assert_is_list, value, "value")


def test_a_dictionary_passes():
    assert_passes(validation.assert_is_dictionary, {}, "value")


@pytest.mark.parametrize("value", [[], "text", None])
def test_a_non_dictionary_is_rejected(value):
    assert_rejects(validation.assert_is_dictionary, value, "value")


def test_a_present_key_passes():
    assert_passes(validation.assert_dictionary_has_key, {"key": 1}, "key")


def test_a_missing_key_is_rejected():
    assert_rejects(validation.assert_dictionary_has_key, {}, "key")


def test_a_key_check_on_a_non_dictionary_is_rejected():
    assert_rejects(validation.assert_dictionary_has_key, ["key"], "key")


###########################################################
# Callables and paths
###########################################################

def test_a_callable_passes():
    assert_passes(validation.assert_callable, len, "value")
    assert_passes(validation.assert_callable, lambda: None, "value")


@pytest.mark.parametrize("value", [1, "text", None])
def test_a_non_callable_is_rejected(value):
    assert_rejects(validation.assert_callable, value, "value")


def test_an_existing_path_passes(tmp_path):
    assert_passes(validation.assert_path_exists, str(tmp_path), "value")


def test_a_missing_path_is_rejected(tmp_path):
    assert_rejects(validation.assert_path_exists, str(tmp_path / "absent"), "value")


def test_a_valid_path_passes():
    assert_passes(validation.assert_is_valid_path, "/tmp/somewhere", "value")


@pytest.mark.parametrize("value", ["", None])
def test_an_invalid_path_is_rejected(value):
    assert_rejects(validation.assert_is_valid_path, value, "value")
