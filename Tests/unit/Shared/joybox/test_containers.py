# Imports
import pytest

# Local imports
from joybox import config, containers


###########################################################
# Search results
#
# Store and metadata searches return these, and find_entry_by_name sorts on
# relevance - so the accessors have to round-trip and not collide.
###########################################################

SEARCH_FIELDS = ["id", "title", "description", "url", "date", "relevance", "data"]
ASSET_FIELDS = ["mime", "width", "height", "duration"]


@pytest.mark.parametrize("field", SEARCH_FIELDS)
def test_every_search_field_round_trips(field):
    result = containers.SearchResult()
    getattr(result, f"set_{field}")("value")

    assert getattr(result, f"get_{field}")() == "value"


@pytest.mark.parametrize("field", SEARCH_FIELDS)
def test_an_unset_search_field_is_none(field):
    assert getattr(containers.SearchResult(), f"get_{field}")() is None


def test_search_fields_do_not_collide():
    result = containers.SearchResult()
    for field in SEARCH_FIELDS:
        getattr(result, f"set_{field}")(f"value-{field}")

    assert len(result.get_data_copy()) == len(SEARCH_FIELDS)
    for field in SEARCH_FIELDS:
        assert getattr(result, f"get_{field}")() == f"value-{field}"


def test_relevance_keeps_its_numeric_type():
    # find_entry_by_name sorts on this, so a string would order lexically.
    result = containers.SearchResult()
    result.set_relevance(95)

    assert result.get_relevance() == 95


def test_arbitrary_data_is_carried_through():
    payload = {"nested": {"value": 1}}
    result = containers.SearchResult()
    result.set_data(payload)

    assert result.get_data() == payload


def test_results_sort_by_relevance():
    results = []
    for relevance in [50, 95, 70]:
        result = containers.SearchResult()
        result.set_relevance(relevance)
        results.append(result)

    ordered = sorted(results, key = lambda entry: entry.get_relevance(), reverse = True)

    assert [entry.get_relevance() for entry in ordered] == [95, 70, 50]


###########################################################
# Asset results
###########################################################

@pytest.mark.parametrize("field", ASSET_FIELDS)
def test_every_asset_field_round_trips(field):
    result = containers.AssetSearchResult()
    getattr(result, f"set_{field}")("value")

    assert getattr(result, f"get_{field}")() == "value"


@pytest.mark.parametrize("field", SEARCH_FIELDS)
def test_an_asset_result_keeps_the_search_fields(field):
    # AssetSearchResult extends SearchResult, so it has to carry both sets.
    result = containers.AssetSearchResult()
    getattr(result, f"set_{field}")("value")

    assert getattr(result, f"get_{field}")() == "value"


def test_asset_fields_do_not_collide_with_search_fields():
    result = containers.AssetSearchResult()
    for field in SEARCH_FIELDS + ASSET_FIELDS:
        getattr(result, f"set_{field}")(f"value-{field}")

    assert len(result.get_data_copy()) == len(SEARCH_FIELDS) + len(ASSET_FIELDS)


def test_an_asset_result_is_a_search_result():
    assert isinstance(containers.AssetSearchResult(), containers.SearchResult)


###########################################################
# Construction
###########################################################

def test_a_result_can_be_built_from_existing_data():
    result = containers.SearchResult({config.search_result_key_title: "Title"})

    assert result.get_title() == "Title"


def test_two_results_do_not_share_state():
    first = containers.SearchResult()
    second = containers.SearchResult()
    first.set_title("First")

    assert second.get_title() is None
