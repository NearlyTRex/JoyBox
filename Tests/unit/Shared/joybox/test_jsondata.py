# Imports
import pytest

# Local imports
from joybox import config, jsondata


###########################################################
# JsonData
#
# fill_value and fill_subvalue decide whether a metadata write overwrites what
# a user already has. The three categories come from the platform, so the tests
# use a real one rather than a synthetic platform.
###########################################################

PLATFORM = config.Platform.COMPUTER_PUPPET_COMBO

AUTOFILL_KEY = "files"
FILLONCE_KEY = "appname"
MERGE_KEY = "paths"
UNCATEGORISED_KEY = "not_a_categorised_key"


def build(data = None):
    return jsondata.JsonData(data if data is not None else {}, PLATFORM)


###########################################################
# Accessors
###########################################################

def test_a_value_is_read_back():
    assert build({"name": "Game"}).get_value("name") == "Game"


def test_a_missing_value_returns_the_default():
    assert build().get_value("absent", "fallback") == "fallback"


def test_a_subvalue_is_read_back():
    assert build({"store": {"appid": "1"}}).get_subvalue("store", "appid") == "1"


def test_a_missing_subvalue_returns_the_default():
    assert build({"store": {}}).get_subvalue("store", "absent", "fallback") == "fallback"


def test_a_subvalue_under_a_missing_key_returns_the_default():
    assert build().get_subvalue("absent", "sub", "fallback") == "fallback"


def test_key_presence_is_reported():
    data = build({"store": {"appid": "1"}})

    assert data.has_key("store") is True
    assert data.has_key("absent") is False
    assert data.has_subkey("store", "appid") is True
    assert data.has_subkey("store", "absent") is False
    assert data.has_subkey("absent", "appid") is False


###########################################################
# Writing
###########################################################

def test_a_value_is_written():
    data = build()
    data.set_value("name", "Game")

    assert data.get_value("name") == "Game"


def test_a_subvalue_is_written_under_an_existing_key():
    data = build({"store": {}})
    data.set_subvalue("store", "appid", "1")

    assert data.get_subvalue("store", "appid") == "1"


def test_writing_a_subvalue_without_a_parent_is_a_silent_no_op():
    # The parent key has to be created first; the KeyError is swallowed.
    data = build()
    data.set_subvalue("missing", "sub", "value")

    assert data.get_data() == {}


###########################################################
# Fill categories
###########################################################

def test_an_autofill_key_overwrites():
    data = build({AUTOFILL_KEY: "original"})
    data.fill_value(AUTOFILL_KEY, "replacement")

    assert data.get_value(AUTOFILL_KEY) == "replacement"


def test_an_autofill_key_is_written_when_absent():
    data = build()
    data.fill_value(AUTOFILL_KEY, "value")

    assert data.get_value(AUTOFILL_KEY) == "value"


def test_a_fillonce_key_is_written_when_absent():
    data = build({"store": {}})
    data.fill_subvalue("store", FILLONCE_KEY, "derived")

    assert data.get_subvalue("store", FILLONCE_KEY) == "derived"


def test_a_fillonce_key_is_never_overwritten():
    # What keeps a re-run from rewriting an appname the user already has.
    data = build({"store": {FILLONCE_KEY: "existing"}})
    data.fill_subvalue("store", FILLONCE_KEY, "derived")

    assert data.get_subvalue("store", FILLONCE_KEY) == "existing"


def test_a_fillonce_key_is_not_overwritten_even_by_an_empty_value():
    data = build({"store": {FILLONCE_KEY: ""}})
    data.fill_subvalue("store", FILLONCE_KEY, "derived")

    assert data.get_subvalue("store", FILLONCE_KEY) == ""


def test_a_merge_key_combines_both_sides():
    data = build({MERGE_KEY: ["a"]})
    data.fill_value(MERGE_KEY, ["b"])

    assert data.get_value(MERGE_KEY) == ["a", "b"]


def test_a_merge_key_deduplicates():
    data = build({MERGE_KEY: ["a"]})
    data.fill_value(MERGE_KEY, ["a"])

    assert data.get_value(MERGE_KEY) == ["a"]


def test_a_merge_key_is_written_when_absent():
    data = build()
    data.fill_value(MERGE_KEY, ["a"])

    assert data.get_value(MERGE_KEY) == ["a"]


def test_an_uncategorised_key_is_not_written():
    # A key in none of the three lists falls through every branch.
    data = build()
    data.fill_value(UNCATEGORISED_KEY, "value")

    assert data.has_key(UNCATEGORISED_KEY) is False


def test_filling_without_a_platform_writes_nothing():
    # No platform means no category lookup, so every fill is a no-op.
    data = jsondata.JsonData({}, None)
    data.fill_value(AUTOFILL_KEY, "value")

    assert data.get_data() == {}


###########################################################
# Copying
###########################################################

def test_get_data_exposes_the_live_dictionary():
    data = build({"name": "Game"})
    data.get_data()["name"] = "Mutated"

    assert data.get_value("name") == "Mutated"


def test_get_data_copy_is_detached():
    data = build({"meta": {"year": 1995}})
    duplicate = data.get_data_copy()
    duplicate["meta"]["year"] = 2024

    assert data.get_subvalue("meta", "year") == 1995


def test_copying_the_object_is_deep():
    data = build({"meta": {"year": 1995}})
    duplicate = data.copy()
    duplicate.set_subvalue("meta", "year", 2024)

    assert data.get_subvalue("meta", "year") == 1995


def test_platform_is_carried_on_the_copy():
    assert build().copy().get_platform() == PLATFORM
