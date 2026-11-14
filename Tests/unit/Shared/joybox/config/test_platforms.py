# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.config import categories
from joybox.config import keys
from joybox.config import types

ALL_PLATFORMS = config.Platform.members()
PLATFORM_IDS = [platform.name for platform in ALL_PLATFORMS]
COMPUTER_PLATFORMS = [platform for platform in ALL_PLATFORMS if config.platforms[platform][keys.platform_key_category] == categories.Category.COMPUTER]
COMPUTER_IDS = [platform.name for platform in COMPUTER_PLATFORMS]
CONSOLE_PLATFORMS = [platform for platform in ALL_PLATFORMS if platform not in COMPUTER_PLATFORMS]
CONSOLE_IDS = [platform.name for platform in CONSOLE_PLATFORMS]
SECTION_FIELDS = {
    keys.platform_key_supercategory,
    keys.platform_key_category,
    keys.platform_key_subcategory,
    keys.platform_key_addons,
    keys.platform_key_launcher,
    keys.platform_key_autofill_json,
    keys.platform_key_fillonce_json,
    keys.platform_key_merge_json
}
JSON_FIELDS = [keys.platform_key_autofill_json, keys.platform_key_fillonce_json, keys.platform_key_merge_json]
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
    category = section(platform)[keys.platform_key_category]
    subcategory = section(platform)[keys.platform_key_subcategory]
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
    category = section(platform)[keys.platform_key_category]
    subcategory = section(platform)[keys.platform_key_subcategory]
    assert subcategory.name == platform.name
    assert subcategory in categories.subcategory_map[category]


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_section_is_a_rom_platform(platform):
    assert section(platform)[keys.platform_key_supercategory] == categories.Supercategory.ROMS


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_addons_are_unique_addon_types(platform):
    addons = section(platform)[keys.platform_key_addons]
    assert all(isinstance(addon, types.AddonType) for addon in addons)
    assert len(addons) == len(set(addons))


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_launcher_is_a_single_launch_type(platform):
    launcher = section(platform)[keys.platform_key_launcher]
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
    assert keys.json_key_files in section(platform)[keys.platform_key_autofill_json]


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_transform_file_is_autofilled_exactly_for_transform_platforms(platform):
    autofills_transform = keys.json_key_transform_file in section(platform)[keys.platform_key_autofill_json]
    assert autofills_transform == (platform in config.transform_platforms)


###########################################################
# Console launchers
###########################################################

@pytest.mark.parametrize("platform", CONSOLE_PLATFORMS, ids = CONSOLE_IDS)
def test_console_launcher_has_the_json_key_it_launches_by(platform):
    launch_keys = {
        types.LaunchType.NO_LAUNCHER: set(),
        types.LaunchType.LAUNCH_FILE: {keys.json_key_launch_file},
        types.LaunchType.LAUNCH_NAME: {keys.json_key_launch_name}
    }[section(platform)[keys.platform_key_launcher][0]]
    filled = set(section(platform)[keys.platform_key_autofill_json]) | set(section(platform)[keys.platform_key_fillonce_json])
    assert filled & {keys.json_key_launch_file, keys.json_key_launch_name} == launch_keys


@pytest.mark.parametrize("platform", CONSOLE_PLATFORMS, ids = CONSOLE_IDS)
def test_console_platforms_merge_nothing(platform):
    assert section(platform)[keys.platform_key_merge_json] == []


###########################################################
# Computer platforms
###########################################################

@pytest.mark.parametrize("platform", COMPUTER_PLATFORMS, ids = COMPUTER_IDS)
def test_computer_platform_uses_the_shared_computer_keys(platform):
    assert section(platform)[keys.platform_key_autofill_json] == config.json_keys_autofill_computer
    assert section(platform)[keys.platform_key_fillonce_json] == config.json_keys_fillonce_computer
    assert section(platform)[keys.platform_key_merge_json][:-1] == config.json_keys_merge_computer


@pytest.mark.parametrize("platform", COMPUTER_PLATFORMS, ids = COMPUTER_IDS)
def test_computer_platform_merges_one_store_key(platform):
    store_keys = [json_key for json_key in section(platform)[keys.platform_key_merge_json] if json_key in keys.json_keys_store]
    assert store_keys == [section(platform)[keys.platform_key_merge_json][-1]]


def test_each_store_key_belongs_to_one_computer_platform():
    store_keys = [section(platform)[keys.platform_key_merge_json][-1] for platform in COMPUTER_PLATFORMS]
    assert sorted(store_keys) == sorted(keys.json_keys_store)


def test_computer_merge_keys_are_store_subdata():
    assert set(config.json_keys_merge_computer) <= set(keys.json_keys_store_subdata)
    assert set(config.json_keys_fillonce_computer) <= set(keys.json_keys_store_appdata) | {keys.json_key_store_branchid}


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
