# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.config import categories
from joybox.config import keys
from joybox.config import types

ALL_PLATFORMS = config.Platform.members()
PLATFORM_IDS = [platform.name for platform in ALL_PLATFORMS]
COMPUTER_PLATFORMS = [platform for platform in ALL_PLATFORMS if config.platforms[platform][keys.PLATFORM_KEY_CATEGORY] == categories.Category.COMPUTER]
COMPUTER_IDS = [platform.name for platform in COMPUTER_PLATFORMS]
CONSOLE_PLATFORMS = [platform for platform in ALL_PLATFORMS if platform not in COMPUTER_PLATFORMS]
CONSOLE_IDS = [platform.name for platform in CONSOLE_PLATFORMS]
SECTION_FIELDS = {
    keys.PLATFORM_KEY_SUPERCATEGORY,
    keys.PLATFORM_KEY_CATEGORY,
    keys.PLATFORM_KEY_SUBCATEGORY,
    keys.PLATFORM_KEY_ADDONS,
    keys.PLATFORM_KEY_LAUNCHER,
    keys.PLATFORM_KEY_AUTOFILL_JSON,
    keys.PLATFORM_KEY_FILLONCE_JSON,
    keys.PLATFORM_KEY_MERGE_JSON
}
JSON_FIELDS = [keys.PLATFORM_KEY_AUTOFILL_JSON, keys.PLATFORM_KEY_FILLONCE_JSON, keys.PLATFORM_KEY_MERGE_JSON]
KNOWN_JSON_KEYS = set(keys.persistent_json_keys) | set(keys.json_keys_store_subdata)
PLATFORM_LISTS = ["transform_platforms", "letter_platforms", "manual_import_platforms"]


def section(platform):
    return config.platforms[platform]


###########################################################
# Platform enum
###########################################################

def test_platform_values_are_unique():
    assert len(config.Platform.values()) == len(set(config.Platform.values()))


def test_there_is_one_platform_per_subcategory():
    assert [platform.name for platform in ALL_PLATFORMS] == [subcategory.name for subcategory in categories.Subcategory.members()]


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_platform_value_is_derived_from_its_categories(platform):
    category = section(platform)[keys.PLATFORM_KEY_CATEGORY]
    subcategory = section(platform)[keys.PLATFORM_KEY_SUBCATEGORY]
    expected = category + " - " + subcategory if category == categories.Category.COMPUTER else subcategory.val()
    assert platform.val() == expected


###########################################################
# Platform sections
###########################################################

def test_every_platform_has_a_section():
    assert list(config.platforms) == ALL_PLATFORMS


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_section_has_exactly_the_platform_fields(platform):
    assert set(section(platform)) == SECTION_FIELDS


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_section_names_its_own_subcategory_under_its_category(platform):
    category = section(platform)[keys.PLATFORM_KEY_CATEGORY]
    subcategory = section(platform)[keys.PLATFORM_KEY_SUBCATEGORY]
    assert subcategory.name == platform.name
    assert subcategory in categories.subcategory_map[category]


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_section_is_a_rom_platform(platform):
    assert section(platform)[keys.PLATFORM_KEY_SUPERCATEGORY] == categories.Supercategory.ROMS


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_addons_are_unique_addon_types(platform):
    addons = section(platform)[keys.PLATFORM_KEY_ADDONS]
    assert all(isinstance(addon, types.AddonType) for addon in addons)
    assert len(addons) == len(set(addons))


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_launcher_is_a_single_launch_type(platform):
    launcher = section(platform)[keys.PLATFORM_KEY_LAUNCHER]
    assert len(launcher) == 1
    assert launcher[0] in types.LaunchType.members()


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_json_fields_name_known_json_keys(platform):
    used = [json_key for field in JSON_FIELDS for json_key in section(platform)[field]]
    assert set(used) <= KNOWN_JSON_KEYS


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_json_fields_do_not_overlap(platform):
    used = [json_key for field in JSON_FIELDS for json_key in section(platform)[field]]
    assert len(used) == len(set(used))


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_files_are_always_autofilled(platform):
    assert keys.JSON_KEY_FILES in section(platform)[keys.PLATFORM_KEY_AUTOFILL_JSON]


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_transform_file_is_autofilled_exactly_for_transform_platforms(platform):
    autofills_transform = keys.JSON_KEY_TRANSFORM_FILE in section(platform)[keys.PLATFORM_KEY_AUTOFILL_JSON]
    assert autofills_transform == (platform in config.transform_platforms)


###########################################################
# Console launchers
###########################################################

@pytest.mark.parametrize("platform", CONSOLE_PLATFORMS, ids = CONSOLE_IDS)
def test_console_launcher_has_the_json_key_it_launches_by(platform):
    launch_keys = {
        types.LaunchType.NO_LAUNCHER: set(),
        types.LaunchType.LAUNCH_FILE: {keys.JSON_KEY_LAUNCH_FILE},
        types.LaunchType.LAUNCH_NAME: {keys.JSON_KEY_LAUNCH_NAME}
    }[section(platform)[keys.PLATFORM_KEY_LAUNCHER][0]]
    filled = set(section(platform)[keys.PLATFORM_KEY_AUTOFILL_JSON]) | set(section(platform)[keys.PLATFORM_KEY_FILLONCE_JSON])
    assert filled & {keys.JSON_KEY_LAUNCH_FILE, keys.JSON_KEY_LAUNCH_NAME} == launch_keys


@pytest.mark.parametrize("platform", CONSOLE_PLATFORMS, ids = CONSOLE_IDS)
def test_console_platforms_merge_nothing(platform):
    assert section(platform)[keys.PLATFORM_KEY_MERGE_JSON] == []


###########################################################
# Computer platforms
###########################################################

@pytest.mark.parametrize("platform", COMPUTER_PLATFORMS, ids = COMPUTER_IDS)
def test_computer_platform_uses_the_shared_computer_keys(platform):
    assert section(platform)[keys.PLATFORM_KEY_AUTOFILL_JSON] == config.json_keys_autofill_computer
    assert section(platform)[keys.PLATFORM_KEY_FILLONCE_JSON] == config.json_keys_fillonce_computer
    assert section(platform)[keys.PLATFORM_KEY_MERGE_JSON][:-1] == config.json_keys_merge_computer


@pytest.mark.parametrize("platform", COMPUTER_PLATFORMS, ids = COMPUTER_IDS)
def test_computer_platform_merges_one_store_key(platform):
    store_keys = [json_key for json_key in section(platform)[keys.PLATFORM_KEY_MERGE_JSON] if json_key in keys.json_keys_store]
    assert store_keys == [section(platform)[keys.PLATFORM_KEY_MERGE_JSON][-1]]


def test_each_store_key_belongs_to_one_computer_platform():
    store_keys = [section(platform)[keys.PLATFORM_KEY_MERGE_JSON][-1] for platform in COMPUTER_PLATFORMS]
    assert sorted(store_keys) == sorted(keys.json_keys_store)


def test_computer_merge_keys_are_store_subdata():
    assert set(config.json_keys_merge_computer) <= set(keys.json_keys_store_subdata)
    assert set(config.json_keys_fillonce_computer) <= set(keys.json_keys_store_appdata) | {keys.JSON_KEY_STORE_BRANCHID}


###########################################################
# Platform lists
###########################################################

@pytest.mark.parametrize("name", PLATFORM_LISTS)
def test_platform_list_names_unique_real_platforms(name):
    listed = getattr(config, name)
    assert listed
    assert set(listed) <= set(ALL_PLATFORMS)
    assert len(listed) == len(set(listed))


def test_letter_platforms_are_the_computer_platforms():
    assert config.letter_platforms == COMPUTER_PLATFORMS


def test_manual_import_platforms_are_computer_platforms():
    assert set(config.manual_import_platforms) <= set(COMPUTER_PLATFORMS)


def test_every_computer_platform_is_a_transform_platform():
    assert set(COMPUTER_PLATFORMS) <= set(config.transform_platforms)
