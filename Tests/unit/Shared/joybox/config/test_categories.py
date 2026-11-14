# Third-party imports
import pytest

# Local imports
from joybox.config import categories

ALL_MAPPED = [subcategory for subcategories in categories.subcategory_map.values() for subcategory in subcategories]
MAPPED_PAIRS = [
    (category, subcategory)
    for category, subcategories in categories.subcategory_map.items()
    for subcategory in subcategories
]


###########################################################
# Enum values
###########################################################

@pytest.mark.parametrize("enum_class", [categories.Supercategory, categories.Category, categories.Subcategory],
    ids = ["supercategory", "category", "subcategory"])
def test_enum_values_are_unique(enum_class):
    assert len(enum_class.values()) == len(set(enum_class.values()))


@pytest.mark.parametrize("subcategory", categories.Subcategory.members(), ids = categories.Subcategory.values())
def test_subcategory_value_is_usable_as_a_folder_name(subcategory):
    assert subcategory.val().strip() == subcategory.val()
    assert not set(subcategory.val()) & set("/\\:*?\"<>|")


###########################################################
# Subcategory map
###########################################################

def test_map_has_exactly_one_entry_per_category():
    assert list(categories.subcategory_map) == categories.Category.members()


def test_every_subcategory_is_mapped_exactly_once():
    assert len(ALL_MAPPED) == len(set(ALL_MAPPED))
    assert set(ALL_MAPPED) == set(categories.Subcategory.members())


@pytest.mark.parametrize("category, subcategory", MAPPED_PAIRS, ids = [subcategory.name for _, subcategory in MAPPED_PAIRS])
def test_subcategory_is_mapped_under_its_named_category(category, subcategory):
    assert subcategory.name.startswith(category.name + "_")


@pytest.mark.parametrize("category", categories.Category.members(), ids = categories.Category.values())
def test_map_follows_enum_declaration_order(category):
    declared = [member for member in categories.Subcategory.members() if member.name.startswith(category.name + "_")]
    assert categories.subcategory_map[category] == declared


@pytest.mark.parametrize("category", categories.Category.members(), ids = categories.Category.values())
def test_every_category_has_subcategories(category):
    assert len(categories.subcategory_map[category]) > 0


def test_map_lookup_accepts_category_strings():
    assert categories.subcategory_map["Sony"] == categories.subcategory_map[categories.Category.SONY]
