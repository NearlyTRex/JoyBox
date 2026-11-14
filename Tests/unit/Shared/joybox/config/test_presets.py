# Third-party imports
import pytest

# Local imports
from joybox.config import categories
from joybox.config import presets
from joybox.config import types

GROUPS = list(presets.presets_option_groups.items())
GROUP_IDS = [group_type.val() for group_type, _ in GROUPS]
GROUP_OPTIONS = [options for _, options in GROUPS]


def test_every_option_group_type_has_options():
    assert set(presets.presets_option_groups) == set(types.PresetOptionGroupType.members())


@pytest.mark.parametrize("options", GROUP_OPTIONS, ids = GROUP_IDS)
def test_options_name_real_categories(options):
    assert set(options) - {"subcategories"} == {"supercategory", "category"}
    assert options["supercategory"] in categories.Supercategory.members()
    assert options["category"] in categories.Category.members()


@pytest.mark.parametrize("options", GROUP_OPTIONS, ids = GROUP_IDS)
def test_subcategories_belong_to_the_group_category(options):
    subcategories = options.get("subcategories", categories.subcategory_map[options["category"]])
    assert subcategories
    assert set(subcategories) <= set(categories.subcategory_map[options["category"]])
    assert len(subcategories) == len(set(subcategories))


@pytest.mark.parametrize("category", categories.Category.members(), ids = categories.Category.values())
def test_groups_of_a_category_do_not_back_up_a_subcategory_twice(category):
    selected = [
        subcategory
        for options in GROUP_OPTIONS if options["category"] == category
        for subcategory in options.get("subcategories", categories.subcategory_map[category])
    ]
    assert len(selected) == len(set(selected))


@pytest.mark.parametrize("group_type", [group_type for group_type, _ in GROUPS], ids = GROUP_IDS)
def test_group_name_is_backup_of_its_category(group_type):
    category = presets.presets_option_groups[group_type]["category"]
    assert group_type.val().lower().startswith("backup_" + category.val().lower())
