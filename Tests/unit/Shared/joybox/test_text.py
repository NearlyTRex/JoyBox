# Imports
import pytest

# Local imports
from joybox import config, text


###########################################################
# Title casing
#
# Game names are capitalized on the way into the collection, so this decides
# the display name and, through it, the derived paths.
###########################################################

def test_each_word_is_capitalized():
    assert text.capitalize_text("chrono trigger") == "Chrono Trigger"


def test_filler_words_stay_lowercase():
    assert text.capitalize_text("the legend of zelda") == "The Legend of Zelda"


def test_a_leading_filler_word_is_still_capitalized():
    # Only a filler word after the first position keeps its case.
    assert text.capitalize_text("a link to the past").startswith("A ")


def test_casing_after_the_first_letter_is_preserved():
    # An intentional inner capital must survive.
    assert text.capitalize_text("mcDonald land") == "McDonald Land"


def test_a_single_character_is_capitalized():
    assert text.capitalize_text("a") == "A"


def test_empty_text_stays_empty():
    assert text.capitalize_text("") == ""


def test_repeated_spaces_collapse():
    assert text.capitalize_text("hello  world") == "Hello World"


def test_digits_and_symbols_survive():
    assert text.capitalize_text("sonic 2") == "Sonic 2"


@pytest.mark.parametrize("filler", config.filler_words[:10])
def test_every_filler_word_stays_lowercase_after_the_first_position(filler):
    assert text.capitalize_text(f"word {filler} word") == f"Word {filler} Word"


###########################################################
# Rich text cleaning
###########################################################

def test_accents_are_transliterated():
    assert text.clean_rich_text("Pokémon") == "Pokemon"


def test_symbols_are_replaced():
    assert text.clean_rich_text("Game™") == "Game(tm)"


def test_the_result_is_ascii_only():
    cleaned = text.clean_rich_text("Ünïcödé ☃ Game")

    assert cleaned.isascii()


def test_surrounding_whitespace_is_trimmed():
    assert text.clean_rich_text("  spaced  ") == "spaced"


def test_plain_ascii_survives_unchanged():
    assert text.clean_rich_text("Plain Name") == "Plain Name"


###########################################################
# Wrapping
###########################################################

def test_text_wraps_at_the_width():
    assert text.wrap_text_to_lines("aaa bbb ccc", width = 7) == ["aaa bbb", "ccc"]


def test_no_wrapped_line_exceeds_the_width():
    wrapped = text.wrap_text_to_lines("word " * 40, width = 20)

    assert all(len(line) <= 20 for line in wrapped)


def test_a_spacer_separates_original_lines():
    wrapped = text.wrap_text_to_lines("first\nsecond", width = 80, spacer = "...")

    assert "..." in wrapped


def test_no_spacer_is_added_after_the_last_line():
    wrapped = text.wrap_text_to_lines("first\nsecond", width = 80, spacer = "...")

    assert wrapped[-1] != "..."


###########################################################
# Enclosed substrings
###########################################################

def test_a_quoted_substring_is_found():
    assert text.find_enclosed_substrings('cat "my file" end') == ["my file"]


def test_several_quoted_substrings_are_found():
    assert text.find_enclosed_substrings('"one" and "two"') == ["one", "two"]


def test_nothing_quoted_finds_nothing():
    assert text.find_enclosed_substrings("no quotes here") == []


def test_an_escaped_delimiter_is_not_a_boundary():
    assert text.find_enclosed_substrings(r'"a \" b"') == [r'a \" b']


def test_custom_delimiters_are_honoured():
    assert text.find_enclosed_substrings("a (b) c", "(", ")") == ["b"]


def test_splitting_keeps_a_quoted_run_together():
    assert text.split_by_enclosed_substrings('cat "my file" end') == \
        ["cat", "my file", "end"]


def test_splitting_an_unquoted_string_yields_one_part():
    assert text.split_by_enclosed_substrings("no quotes here") == ["no quotes here"]


def test_splitting_a_fully_quoted_string_yields_the_contents():
    assert text.split_by_enclosed_substrings('"only"') == ["only"]


def test_splitting_drops_empty_parts():
    assert "" not in text.split_by_enclosed_substrings('"a""b"')
