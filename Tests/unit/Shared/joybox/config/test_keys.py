# Third-party imports
import pytest

# Local imports
from joybox.config import keys

KEY_NAMES = [name for name, value in vars(keys).items() if "_KEY_" in name and isinstance(value, str)]
KEY_GROUPS = sorted({name.split("_KEY_", 1)[0].lower() for name in KEY_NAMES})
KEY_LISTS = sorted(name for name, value in vars(keys).items() if "_keys" in name.lower() and isinstance(value, list))


def group_values(group):
    return [getattr(keys, name) for name in KEY_NAMES if name.startswith(group.upper() + "_KEY_")]


###########################################################
# Individual keys
###########################################################

@pytest.mark.parametrize("name", KEY_NAMES)
def test_key_value_matches_its_name(name):
    suffix = name.split("_KEY_", 1)[1].lower()
    for prefix in ("store_setup_", "store_"):
        if suffix != prefix.rstrip("_") and suffix.startswith(prefix):
            suffix = suffix.removeprefix(prefix)
            break
    assert getattr(keys, name) == suffix


@pytest.mark.parametrize("group", KEY_GROUPS)
def test_keys_are_unique_within_their_group(group):
    values = group_values(group)
    assert len(values) == len(set(values))


###########################################################
# Key lists
###########################################################

@pytest.mark.parametrize("name", KEY_LISTS)
def test_key_list_has_no_duplicates(name):
    values = getattr(keys, name)
    assert values
    assert len(values) == len(set(values))


def test_metadata_keys_all_holds_every_metadata_key_in_order():
    assert keys.metadata_keys_all == group_values("metadata")


@pytest.mark.parametrize("name", ["metadata_keys_minimum", "metadata_keys_downloadable"])
def test_metadata_subsets_are_within_all_keys(name):
    assert set(getattr(keys, name)) <= set(keys.metadata_keys_all)


def test_minimum_and_downloadable_metadata_do_not_overlap():
    assert not set(keys.metadata_keys_minimum) & set(keys.metadata_keys_downloadable)


def test_general_json_keys_hold_every_launch_and_content_key():
    general_names = [
        "JSON_KEY_LAUNCH_NAME", "JSON_KEY_LAUNCH_FILE", "JSON_KEY_LAUNCH_DIR", "JSON_KEY_TRANSFORM_FILE",
        "JSON_KEY_KEY_FILE", "JSON_KEY_FILES", "JSON_KEY_DLC", "JSON_KEY_UPDATE", "JSON_KEY_EXTRA", "JSON_KEY_DEPENDENCIES"]
    assert keys.json_keys_general == [getattr(keys, name) for name in general_names]


def test_store_appdata_is_a_prefix_of_store_subdata():
    assert keys.json_keys_store_subdata[:len(keys.json_keys_store_appdata)] == keys.json_keys_store_appdata


def test_store_subdata_holds_every_top_level_store_key():
    top_level = [getattr(keys, name) for name in KEY_NAMES if name.startswith("JSON_KEY_STORE_") and not name.startswith("JSON_KEY_STORE_SETUP_")]
    assert sorted(keys.json_keys_store_subdata) == sorted(top_level)


def test_virtual_keys_are_not_persistent():
    assert not set(keys.json_keys_virtual) & set(keys.persistent_json_keys)


def test_persistent_keys_are_general_then_store_keys():
    assert keys.persistent_json_keys == keys.json_keys_general + keys.json_keys_store
