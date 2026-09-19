# Imports
import pytest

# Local imports
from joybox import datautils


###########################################################
# List merging
###########################################################

def test_merging_lists_unions_and_sorts():
    assert datautils.merge_lists(["b", "a"], ["c", "a"]) == ["a", "b", "c"]


def test_merging_lists_deduplicates():
    assert datautils.merge_lists(["a", "a"], ["a"]) == ["a"]


def test_merging_a_list_with_a_non_list_keeps_the_list():
    assert datautils.merge_lists(["a"], None) == ["a"]
    assert datautils.merge_lists(None, ["b"]) == ["b"]


def test_merging_two_non_lists_is_none():
    assert datautils.merge_lists(None, None) is None


###########################################################
# Dictionary merging
###########################################################

def test_merging_a_dictionary_with_a_non_dictionary_keeps_the_dictionary():
    assert datautils.merge_dictionaries({"a": 1}, None) == {"a": 1}
    assert datautils.merge_dictionaries(None, {"b": 2}) == {"b": 2}


def test_merging_two_non_dictionaries_is_none():
    assert datautils.merge_dictionaries(None, None) is None


###########################################################
# Data merging
###########################################################

def test_merge_data_dispatches_on_type():
    assert datautils.merge_data(["a"], ["b"]) == ["a", "b"]
    assert datautils.merge_data("a", "b") == ["a", "b"]


def test_merge_data_with_one_empty_side_returns_the_other():
    assert datautils.merge_data("a", None) == "a"
    assert datautils.merge_data(None, "b") == "b"
    assert datautils.merge_data(None, None) is None


###########################################################
# Adjacent deduplication
###########################################################

def test_adjacent_duplicates_collapse():
    assert datautils.deduplicate_adjacent_lines(["a", "a", "b", "b", "a"]) == ["a", "b", "a"]


def test_non_adjacent_duplicates_are_kept():
    # "adjacent" is the whole contract - this is for collapsing repeated log
    # lines, not for uniquing a list.
    assert datautils.deduplicate_adjacent_lines(["a", "b", "a"]) == ["a", "b", "a"]


def test_deduplicating_an_empty_list():
    assert datautils.deduplicate_adjacent_lines([]) == []


###########################################################
# Iterable detection
###########################################################

@pytest.mark.parametrize("value", [[], (), {}, set()])
def test_containers_are_iterable_non_strings(value):
    assert datautils.is_iterable_non_string(value) is True


def test_a_string_is_iterable_but_not_an_iterable_non_string():
    # The distinction that matters: iterating a string yields characters, which
    # is almost never what a caller walking a container wants.
    assert datautils.is_iterable_container("abc") is True
    assert datautils.is_iterable_non_string("abc") is False


@pytest.mark.parametrize("value", [1, None, object()])
def test_scalars_are_not_iterable(value):
    assert datautils.is_iterable_non_string(value) is False


###########################################################
# Dictionary search
#
# search_json_files is the only caller, and it decides whether a file matched.
# A missed match there is a silently incomplete search result.
###########################################################

def test_a_top_level_match_is_found():
    assert datautils.search_dictionary({"name": "Chrono Trigger"}, "Chrono") == \
        [("name", "Chrono Trigger")]


def test_a_nested_match_is_found():
    assert datautils.search_dictionary({"meta": {"name": "Chrono"}}, "Chrono") == \
        [("name", "Chrono")]


def test_a_match_after_a_nested_dictionary_is_found():
    # The recursion must not abandon later siblings.
    data = {"a": "no", "b": {"deep": "nope"}, "c": "FINDME here"}
    assert datautils.search_dictionary(data, "FINDME") == [("c", "FINDME here")]


def test_a_match_after_several_nested_dictionaries_is_found():
    data = {"a": {"n": "no"}, "b": {"m": "no"}, "c": "FINDME"}
    assert datautils.search_dictionary(data, "FINDME") == [("c", "FINDME")]


def test_a_match_in_a_later_branch_is_found():
    data = {"first": {"x": "no"}, "second": {"y": "FINDME"}}
    assert datautils.search_dictionary(data, "FINDME") == [("y", "FINDME")]


def test_no_match_returns_empty():
    assert datautils.search_dictionary({"a": "x", "b": {"c": "y"}}, "NOPE") == []


def test_search_keys_restrict_which_keys_match():
    data = {"title": "FINDME", "description": "FINDME"}
    assert datautils.search_dictionary(data, "FINDME", ["description"]) == \
        [("description", "FINDME")]


def test_non_dictionary_input_returns_empty():
    assert datautils.search_dictionary(["not", "a", "dict"], "not") == []
    assert datautils.search_dictionary(None, "anything") == []


###########################################################
# Retry with backoff
#
# Callers are web scrapes whose "no results found" path returns None, so a None
# on the first attempt is not retried. A None after an exception is, since
# something is already broken.
###########################################################

def test_a_successful_call_is_not_retried():
    calls = []

    def succeed():
        calls.append(1)
        return "value"

    assert datautils.retry_with_backoff(succeed, max_retries = 3, initial_delay = 0) == "value"
    assert len(calls) == 1


def test_a_first_attempt_returning_none_is_accepted():
    # "Nothing found" is a legitimate answer, not a failure to retry through.
    calls = []

    def find_nothing():
        calls.append(1)
        return None

    assert datautils.retry_with_backoff(find_nothing, max_retries = 3, initial_delay = 0) is None
    assert len(calls) == 1, "a clean empty result must not trigger a retry storm"


def test_an_exception_is_retried_until_it_succeeds():
    attempts = []

    def flaky():
        attempts.append(1)
        if len(attempts) < 3:
            raise RuntimeError("boom")
        return "recovered"

    assert datautils.retry_with_backoff(flaky, max_retries = 5, initial_delay = 0) == "recovered"
    assert len(attempts) == 3


def test_retries_give_up_and_return_none():
    attempts = []

    def always_raise():
        attempts.append(1)
        raise RuntimeError("boom")

    assert datautils.retry_with_backoff(always_raise, max_retries = 3, initial_delay = 0) is None
    assert len(attempts) == 3


def test_none_after_an_exception_keeps_retrying():
    # Once something has thrown, None means still-broken rather than empty.
    attempts = []

    def raise_then_none():
        attempts.append(1)
        if len(attempts) == 1:
            raise RuntimeError("boom")
        return None

    assert datautils.retry_with_backoff(raise_then_none, max_retries = 4, initial_delay = 0) is None
    assert len(attempts) > 2, "a None after a failure should not end the run early"


def test_cleanup_runs_after_a_failed_attempt():
    cleanups = []

    def always_raise():
        raise RuntimeError("boom")

    datautils.retry_with_backoff(
        always_raise,
        cleanup_func = lambda: cleanups.append(1),
        max_retries = 3,
        initial_delay = 0)

    assert len(cleanups) == 3


def test_cleanup_does_not_run_when_the_call_succeeds():
    cleanups = []

    datautils.retry_with_backoff(
        lambda: "value",
        cleanup_func = lambda: cleanups.append(1),
        max_retries = 3,
        initial_delay = 0)

    assert cleanups == []


def test_a_failing_cleanup_does_not_mask_the_retry():
    # Cleanup tears down a selenium driver; a failure there must not propagate.
    attempts = []

    def flaky():
        attempts.append(1)
        if len(attempts) < 2:
            raise RuntimeError("boom")
        return "recovered"

    def bad_cleanup():
        raise RuntimeError("cleanup exploded")

    assert datautils.retry_with_backoff(
        flaky,
        cleanup_func = bad_cleanup,
        max_retries = 3,
        initial_delay = 0) == "recovered"
