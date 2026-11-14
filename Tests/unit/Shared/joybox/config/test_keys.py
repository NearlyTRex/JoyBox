# Third-party imports
import pytest

# Local imports
from joybox.config import keys

KEY_NAMES = [name for name, value in vars(keys).items() if "_key_" in name and isinstance(value, str)]
KEY_GROUPS = sorted({name.split("_key_", 1)[0] for name in KEY_NAMES})
KEY_LISTS = sorted(name for name, value in vars(keys).items() if "_keys" in name and isinstance(value, list))


def group_values(group):
    return [getattr(keys, name) for name in KEY_NAMES if name.startswith(group + "_key_")]


###########################################################
# Individual keys
###########################################################

@pytest.mark.parametrize("name", KEY_NAMES)
def test_key_value_matches_its_name(name):
    suffix = name.split("_key_", 1)[1]
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
        "json_key_launch_name", "json_key_launch_file", "json_key_launch_dir", "json_key_transform_file",
        "json_key_key_file", "json_key_files", "json_key_dlc", "json_key_update", "json_key_extra", "json_key_dependencies"]
    assert keys.json_keys_general == [getattr(keys, name) for name in general_names]


def test_store_appdata_is_a_prefix_of_store_subdata():
    assert keys.json_keys_store_subdata[:len(keys.json_keys_store_appdata)] == keys.json_keys_store_appdata


def test_store_subdata_holds_every_top_level_store_key():
    top_level = [getattr(keys, name) for name in KEY_NAMES if name.startswith("json_key_store_") and not name.startswith("json_key_store_setup_")]
    assert sorted(keys.json_keys_store_subdata) == sorted(top_level)


def test_virtual_keys_are_not_persistent():
    assert not set(keys.json_keys_virtual) & set(keys.persistent_json_keys)


def test_persistent_keys_are_general_then_store_keys():
    assert keys.persistent_json_keys == keys.json_keys_general + keys.json_keys_store
