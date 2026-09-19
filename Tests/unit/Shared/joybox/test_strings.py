# Imports
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
