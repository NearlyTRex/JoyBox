# Imports
import pytest

# Local imports
from joybox import reports


###########################################################
# List summarization
#
# Long scan results are trimmed to a head and tail with a count of what was
# hidden. The count is the only way to tell how much was left out, so it has to
# be right.
###########################################################

def summarize(count, max_display = 20):
    return reports.get_summarized_list(list(range(count)), max_display)


###########################################################
# Short lists
###########################################################

def test_a_short_list_is_returned_whole():
    summarized, total, trimmed = summarize(5)

    assert summarized == list(range(5))
    assert total == 5
    assert trimmed is False


def test_a_list_at_the_limit_is_not_trimmed():
    summarized, total, trimmed = summarize(20)

    assert summarized == list(range(20))
    assert trimmed is False


def test_an_empty_list_is_returned_whole():
    summarized, total, trimmed = reports.get_summarized_list([])

    assert summarized == []
    assert total == 0
    assert trimmed is False


def test_the_original_list_is_not_returned():
    # Callers log the result; handing back the caller's own list invites a
    # later append into the scan results.
    items = [1, 2, 3]
    summarized, _, _ = reports.get_summarized_list(items)

    assert summarized is not items


def test_summarizing_does_not_change_the_input():
    items = list(range(50))
    reports.get_summarized_list(items)

    assert items == list(range(50))


def test_a_tuple_is_accepted():
    summarized, total, trimmed = reports.get_summarized_list(tuple(range(3)))

    assert summarized == [0, 1, 2]
    assert total == 3


###########################################################
# Long lists
###########################################################

def test_a_long_list_is_trimmed():
    summarized, total, trimmed = summarize(100)

    assert trimmed is True
    assert total == 100
    assert len(summarized) == 21


def test_the_head_and_tail_are_kept():
    summarized, _, _ = summarize(100)

    assert summarized[:10] == list(range(10))
    assert summarized[-10:] == list(range(90, 100))


def test_the_marker_sits_between_the_head_and_tail():
    summarized, _, _ = summarize(100)

    assert summarized[10] == "... (80 more items) ..."


def test_the_hidden_count_matches_what_is_missing():
    summarized, total, _ = summarize(100)

    shown = [entry for entry in summarized if not isinstance(entry, str)]
    assert "(%d more items)" % (total - len(shown)) in summarized[10]


@pytest.mark.parametrize("count", [21, 25, 50, 100, 1000])
def test_the_hidden_count_is_right_at_any_size(count):
    summarized, total, _ = summarize(count)

    shown = [entry for entry in summarized if not isinstance(entry, str)]
    assert "(%d more items)" % (total - len(shown)) in summarized[len(summarized) // 2]


def test_one_item_over_the_limit_is_still_trimmed():
    summarized, total, trimmed = summarize(21)

    assert trimmed is True
    assert summarized[10] == "... (1 more items) ..."


###########################################################
# Display limits
###########################################################

@pytest.mark.parametrize("max_display", [2, 3, 4, 5, 6, 7, 10, 11])
def test_the_hidden_count_is_right_for_any_limit(max_display):
    # An odd limit shows one fewer item than it allows, and the count has to
    # follow the items actually shown, not the limit.
    items = list(range(100))
    summarized, total, _ = reports.get_summarized_list(items, max_display)

    shown = [entry for entry in summarized if not isinstance(entry, str)]
    assert "(%d more items)" % (total - len(shown)) in summarized[len(summarized) // 2]


@pytest.mark.parametrize("max_display", [0, 1])
def test_a_limit_below_two_shows_no_items(max_display):
    # A zero length tail slice must mean nothing, not the entire list.
    items = list(range(10))
    summarized, total, trimmed = reports.get_summarized_list(items, max_display)

    assert trimmed is True
    assert summarized == ["... (10 more items) ..."]


def test_a_custom_limit_is_honoured():
    summarized, _, trimmed = reports.get_summarized_list(list(range(10)), max_display = 4)

    assert trimmed is True
    assert summarized == [0, 1, "... (6 more items) ...", 8, 9]


def test_a_large_limit_never_trims():
    summarized, _, trimmed = reports.get_summarized_list(list(range(10)), max_display = 1000)

    assert trimmed is False
    assert summarized == list(range(10))


###########################################################
# Reports
###########################################################

def test_a_report_file_holds_every_item(tmp_path):
    # The log is trimmed; the file is what the user greps.
    target = tmp_path / "missing.txt"
    reports.write_list_report(
        [str(index) for index in range(100)], report_file = str(target))

    assert target.read_text().splitlines() == [str(index) for index in range(100)]


def test_a_report_file_is_written_for_a_short_list(tmp_path):
    target = tmp_path / "missing.txt"

    assert reports.write_list_report(["a", "b"], report_file = str(target)) is True
    assert target.read_text().splitlines() == ["a", "b"]


def test_no_report_file_is_written_for_an_empty_list(tmp_path):
    # An empty file reads as "nothing is missing", which is what it means, but
    # a stale one from a previous run would lie.
    target = tmp_path / "missing.txt"

    assert reports.write_list_report([], report_file = str(target)) is True
    assert not target.exists()


def test_a_report_succeeds_without_a_file():
    assert reports.write_list_report(["a", "b"]) is True


def test_non_string_items_are_written(tmp_path):
    target = tmp_path / "missing.txt"
    reports.write_list_report([1, 2, 3], report_file = str(target))

    assert target.read_text().splitlines() == ["1", "2", "3"]


def test_pretending_does_not_write_a_report(tmp_path):
    target = tmp_path / "missing.txt"
    reports.write_list_report(["a", "b"], report_file = str(target), pretend_run = True)

    assert not target.exists()
