# Imports
import pytest

# Local imports
from joybox import config, platforms


###########################################################
# Platform registry
#
# The json key categories decide whether a metadata write overwrites what the
# user already has, so an uncategorised key is silently never written.
###########################################################

ALL_PLATFORMS = config.Platform.members()
PLATFORM_IDS = [str(platform) for platform in ALL_PLATFORMS]


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_every_platform_is_registered(platform):
    assert platforms.is_platform_valid(platform) is True


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_every_platform_has_a_section(platform):
    assert platforms.get_platform_section(platform) is config.platforms[platform]


def test_an_unknown_platform_is_invalid():
    assert platforms.is_platform_valid("not-a-platform") is False
    assert platforms.is_platform_valid(None) is False


def test_an_unknown_platform_has_no_section():
    assert platforms.get_platform_section("not-a-platform") is None


def test_a_missing_key_returns_nothing():
    assert platforms.get_platform_value(ALL_PLATFORMS[0], "not-a-key") is None


def test_a_value_is_read_from_the_section():
    platform = ALL_PLATFORMS[0]

    assert platforms.get_platform_value(platform, config.platform_key_addons) == \
        config.platforms[platform][config.platform_key_addons]


###########################################################
# Classification
###########################################################

def test_letter_platforms_are_a_subset_of_all_platforms():
    unregistered = [platform for platform in config.letter_platforms if not platforms.is_platform_valid(platform)]

    assert not unregistered, unregistered


def test_transform_platforms_are_a_subset_of_all_platforms():
    unregistered = [platform for platform in config.transform_platforms if not platforms.is_platform_valid(platform)]

    assert not unregistered, unregistered


def test_an_unknown_platform_is_not_classified():
    assert platforms.is_letter_platform("not-a-platform") is False
    assert platforms.is_transform_platform("not-a-platform") is False
    assert platforms.is_letter_platform(None) is False
    assert platforms.is_transform_platform(None) is False


###########################################################
# Addons
###########################################################

@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_every_platform_declares_addon_types(platform):
    declared = platforms.get_addon_types(platform)

    assert set(declared) <= set(config.AddonType.members()), f"{platform} declares {declared}"


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_addon_possibility_agrees_with_the_declared_types(platform):
    declared = platforms.get_addon_types(platform)

    assert platforms.are_updates_possible(platform) == (config.AddonType.UPDATES in declared)
    assert platforms.are_dlc_possible(platform) == (config.AddonType.DLC in declared)


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_addons_are_possible_when_any_type_is_declared(platform):
    expected = platforms.are_updates_possible(platform) or platforms.are_dlc_possible(platform)

    assert platforms.are_addons_possible(platform) == expected


###########################################################
# Launchers
###########################################################

@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_every_platform_declares_launcher_types(platform):
    declared = platforms.get_launcher_types(platform)

    assert declared, f"{platform} declares no launcher types"
    assert set(declared) <= set(config.LaunchType.members()), declared


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_a_platform_is_launched_one_way(platform):
    # Name, file, or not at all - never two at once.
    ways = [
        platforms.has_no_launcher(platform),
        platforms.is_launched_by_name(platform),
        platforms.is_launched_by_file(platform),
    ]

    assert sum(1 for way in ways if way) <= 1, f"{platform} declares conflicting launchers"


###########################################################
# Json key categories
###########################################################

@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_the_key_categories_do_not_overlap(platform):
    # A key in two categories takes whichever branch fill_value checks first,
    # so the other category silently never applies.
    autofill = set(platforms.get_autofill_json_keys(platform) or [])
    fillonce = set(platforms.get_fillonce_json_keys(platform) or [])
    merge = set(platforms.get_merge_json_keys(platform) or [])

    assert not (autofill & fillonce), f"{platform}: {sorted(autofill & fillonce)}"
    assert not (autofill & merge), f"{platform}: {sorted(autofill & merge)}"
    assert not (fillonce & merge), f"{platform}: {sorted(fillonce & merge)}"


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_category_membership_matches_the_lists(platform):
    unmatched = [
        (listing.__name__, key) for listing, member in [
            (platforms.get_autofill_json_keys, platforms.is_autofill_json_key),
            (platforms.get_fillonce_json_keys, platforms.is_fillonce_json_key),
            (platforms.get_merge_json_keys, platforms.is_merge_json_key)]
        for key in listing(platform) or [] if member(platform, key) is not True]

    assert not unmatched, unmatched


@pytest.mark.parametrize("platform", ALL_PLATFORMS, ids = PLATFORM_IDS)
def test_an_uncategorised_key_is_in_no_category(platform):
    assert platforms.is_autofill_json_key(platform, "not-a-key") is False
    assert platforms.is_fillonce_json_key(platform, "not-a-key") is False
    assert platforms.is_merge_json_key(platform, "not-a-key") is False


def test_an_unknown_platform_has_no_categories():
    assert platforms.is_autofill_json_key("not-a-platform", "files") is False
    assert platforms.is_fillonce_json_key("not-a-platform", "appname") is False
    assert platforms.is_merge_json_key("not-a-platform", "paths") is False
