# Imports
import sys
from datetime import datetime, timedelta

import pytest

# Local imports
from joybox import strings


###########################################################
# Prefix and suffix handling
###########################################################

def test_prefix_matching_ignores_case_by_default():
    assert strings.does_string_start_with_substring("HelloWorld", "hello") is True


def test_prefix_matching_can_be_case_sensitive():
    assert strings.does_string_start_with_substring("HelloWorld", "hello", case_sensitive = True) is False


def test_suffix_matching_ignores_case_by_default():
    assert strings.does_string_end_with_substring("archive.ZIP", ".zip") is True


def test_a_prefix_is_trimmed():
    assert strings.trim_substring_from_start("prefix_value", "prefix_") == "value"


def test_a_suffix_is_trimmed():
    assert strings.trim_substring_from_end("value.txt", ".txt") == "value"


def test_trimming_something_absent_leaves_the_string_alone():
    assert strings.trim_substring_from_start("value", "nope") == "value"
    assert strings.trim_substring_from_end("value", "nope") == "value"


def test_trimming_an_empty_substring_is_a_no_op():
    # string[:-0] would return an empty string.
    assert strings.trim_substring_from_end("hello", "") == "hello"
    assert strings.trim_substring_from_start("hello", "") == "hello"


def test_trimming_is_case_insensitive_by_default():
    assert strings.trim_substring_from_end("archive.ZIP", ".zip") == "archive"


###########################################################
# Sorting
###########################################################

def test_strings_sort_alphabetically():
    assert strings.sort_strings(["c", "a", "b"]) == ["a", "b", "c"]


def test_sorting_accepts_a_set():
    # prune_paths passes a set straight in.
    assert strings.sort_strings({"c", "a", "b"}) == ["a", "b", "c"]


def test_length_sorting_puts_shorter_strings_first():
    assert strings.sort_strings_with_length(["ccc", "a", "bb"]) == ["a", "bb", "ccc"]


def test_length_sorting_breaks_ties_alphabetically():
    assert strings.sort_strings_with_length(["bb", "aa"]) == ["aa", "bb"]


###########################################################
# Escape and tag removal
###########################################################

def test_ansi_escape_sequences_are_removed():
    # Command output is logged, so colour codes must not reach the log file.
    assert strings.remove_string_escape_sequences("\x1b[31mred\x1b[0m") == "red"


def test_plain_text_survives_escape_removal():
    assert strings.remove_string_escape_sequences("plain") == "plain"


def test_html_tags_are_removed():
    assert strings.remove_string_tag_sequences("<b>bold</b> text") == "bold text"


def test_text_without_tags_survives():
    assert strings.remove_string_tag_sequences("no tags here") == "no tags here"


###########################################################
# Slugs
#
# Slugs are persisted as the store appname, so the shape is a data format.
###########################################################

def test_a_slug_is_lowercase_and_underscored():
    assert strings.get_slug_string("Hello World") == "hello_world"


def test_punctuation_is_dropped_from_a_slug():
    assert strings.get_slug_string("Game: The Sequel!") == "game_the_sequel"


def test_runs_of_separators_collapse():
    assert strings.get_slug_string("a  -  b") == "a_b"
    assert strings.get_slug_string("a - b") == "a_b"


def test_a_slug_has_no_leading_or_trailing_separators():
    assert strings.get_slug_string("-lead-") == "lead"
    assert strings.get_slug_string("  Spaced  ") == "spaced"


def test_a_slug_contains_only_safe_characters():
    slug = strings.get_slug_string("Ünïcödé Game (2024)!")

    assert all(character.islower() or character.isdigit() or character == "_"
               for character in slug), slug


def test_slugging_is_idempotent():
    # A second pass over stored data must not rewrite identifiers.
    for name in ["Hello World", "Game: The Sequel!", "a  -  b"]:
        once = strings.get_slug_string(name)
        assert strings.get_slug_string(once) == once


###########################################################
# URLs
###########################################################

def test_url_components_are_extracted():
    url = "https://example.com/path/page?a=1#frag"

    assert strings.get_url_scheme(url) == "https"
    assert strings.get_url_netloc(url) == "example.com"
    assert strings.get_url_path(url) == "/path/page"
    assert strings.get_url_query(url) == "a=1"
    assert strings.get_url_fragment(url) == "frag"


def test_url_components_are_gathered_together():
    assert strings.get_url_components("https://example.com/p;v=1?a=1#f") == {
        "scheme": "https",
        "netloc": "example.com",
        "path": "/p",
        "params": "v=1",
        "query": "a=1",
        "fragment": "f"}


def test_query_parameters_are_stripped():
    assert strings.strip_string_query_params("https://example.com/p?a=1") == \
        "https://example.com/p"


def test_stripping_keeps_a_url_without_parameters_intact():
    assert strings.strip_string_query_params("https://example.com/p") == \
        "https://example.com/p"


def test_urls_are_joined_relative_to_the_base():
    assert strings.join_strings_as_url("https://example.com/a/b", "c") == \
        "https://example.com/a/c"


def test_url_encoding_escapes_reserved_characters():
    encoded = strings.encode_url_string("a b&c")

    assert " " not in encoded
    assert "&" not in encoded


###########################################################
# Identifiers
###########################################################

def test_generated_ids_are_unique():
    generated = {strings.generate_unique_id() for _ in range(100)}
    assert len(generated) == 100


def test_a_generated_id_is_a_non_empty_string():
    generated = strings.generate_unique_id()

    assert isinstance(generated, str)
    assert generated


###########################################################
# Suffix matching
###########################################################

def test_suffix_matching_can_be_case_sensitive():
    assert strings.does_string_end_with_substring("archive.ZIP", ".zip", case_sensitive = True) is False
    assert strings.does_string_end_with_substring("archive.zip", ".zip", case_sensitive = True) is True


###########################################################
# Enclosed substrings
###########################################################

def test_quoted_substrings_are_removed_with_their_padding():
    assert strings.remove_enclosed_substrings('Game "beta" Edition') == "Game Edition"


def test_quoted_substrings_at_either_end_are_removed():
    assert strings.remove_enclosed_substrings('"x" Game "y"') == "Game"


def test_custom_delimiters_are_honoured():
    assert strings.remove_enclosed_substrings("Game (USA)", "(", ")") == "Game"


###########################################################
# Similarity
###########################################################

def test_similarity_tiers_follow_the_ratio():
    assert strings.are_strings_highly_similar("abcdefghij", "abcdefghiz") is True
    assert strings.are_strings_moderately_similar("abcdefghij", "abcdefghiz") is True
    assert strings.are_strings_possibly_similar("abcd", "abxy") is True
    assert strings.are_strings_possibly_similar("abcd", "wxyz") is False


def test_similarity_without_thefuzz_is_zero(monkeypatch):
    monkeypatch.setitem(sys.modules, "thefuzz", None)

    assert strings.get_string_similarity_ratio("same", "same") == 0


###########################################################
# Dates
###########################################################

def close_to(moment, expected):
    return abs(moment - expected) < timedelta(minutes = 1)


@pytest.mark.parametrize("phrase, delta", [
    ("3 days ago", timedelta(days = 3)),
    ("2 weeks ago", timedelta(weeks = 2)),
    ("yesterday", timedelta(days = 1)),
    ("Today", timedelta(0)),
    ("an hour ago", timedelta(hours = 1)),
])
def test_relative_phrases_are_measured_back_from_now(phrase, delta):
    assert close_to(strings.get_datetime_from_unknown_string(phrase), datetime.now() - delta)


def test_months_and_years_ago_step_back_by_calendar():
    months = strings.get_datetime_from_unknown_string("1 month ago")
    years = strings.get_datetime_from_unknown_string("4 years ago")

    assert timedelta(days = 27) < datetime.now() - months < timedelta(days = 32)
    assert years.year == datetime.now().year - 4


def test_an_absolute_date_is_parsed():
    assert strings.get_datetime_from_unknown_string(" March 5, 2021 ") == datetime(2021, 3, 5)


def test_an_unrecognised_date_is_none():
    assert strings.get_datetime_from_unknown_string("no date here") is None


def test_a_date_is_reformatted():
    assert strings.convert_date_string("2021-03-05", "%Y-%m-%d", "%d/%m/%Y") == "05/03/2021"


def test_a_date_in_another_format_falls_back_to_parsing():
    assert strings.convert_date_string("March 5, 2021", "%Y-%m-%d", "%Y%m%d") == "20210305"


def test_an_unparseable_date_converts_to_none():
    assert strings.convert_date_string("nonsense", "%Y-%m-%d", "%Y") is None


def test_an_unknown_date_string_is_reformatted():
    assert strings.convert_unknown_date_string("March 5, 2021", "%Y") == "2021"
    assert strings.convert_unknown_date_string("nonsense", "%Y") is None


def test_a_formatted_datetime_parses_back():
    moment = strings.get_datetime_from_string("2021-03-05 10:11", "%Y-%m-%d %H:%M")

    assert strings.get_string_from_datetime(moment, "%H:%M") == "10:11"


###########################################################
# Timestamps
###########################################################

def test_an_iso_timestamp_is_utc_seconds():
    assert strings.parse_timestamp("2024-01-02T03:04:05Z") == 1704164645


def test_fractional_seconds_are_dropped():
    assert strings.parse_timestamp("2024-01-02T03:04:05.123Z") == 1704164645


def test_a_space_separated_timestamp_is_local_time():
    expected = int(datetime(2024, 1, 2, 3, 4, 5).timestamp())

    assert strings.parse_timestamp(" 2024-01-02 03:04:05 ") == expected


@pytest.mark.parametrize("value", ["", None, "garbage", "2024-13-40T00:00:00Z"])
def test_a_missing_or_bad_timestamp_is_zero(value):
    assert strings.parse_timestamp(value) == 0


def test_url_encoding_can_use_plus_for_spaces():
    assert strings.encode_url_string("a b", use_plus = True) == "a+b"
