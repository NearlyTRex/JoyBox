# Imports
import pytest

# Local imports
from joybox import audiometadata


###########################################################
# Forced tag overrides
#
# Moved here out of audio_metadata_tool.py and tag_audio_files.py, which each
# carried a byte-identical copy. It parses user input straight off the command
# line, so it is worth testing directly now that it can be.
###########################################################

def test_a_single_override_is_parsed():
    assert audiometadata.parse_force_tags(["genre=Regular"]) == {"genre": "Regular"}


def test_several_overrides_are_parsed():
    parsed = audiometadata.parse_force_tags(["genre=Regular", "album_artist=Various Artists"])

    assert parsed == {"genre": "Regular", "album_artist": "Various Artists"}


def test_a_value_may_contain_an_equals_sign():

    # Split on the first separator only, or a value like a URL loses its tail.
    assert audiometadata.parse_force_tags(["title=a=b=c"]) == {"title": "a=b=c"}


def test_whitespace_around_the_field_is_ignored():
    assert audiometadata.parse_force_tags(["  genre =Regular"]) == {"genre": "Regular"}


def test_a_value_keeps_its_spacing():

    # Track titles and artist names legitimately start or end with spacing the
    # user typed deliberately.
    assert audiometadata.parse_force_tags(["title= Intro "]) == {"title": " Intro "}


@pytest.mark.parametrize("empty", [None, []])
def test_no_overrides_gives_an_empty_mapping(empty):
    assert audiometadata.parse_force_tags(empty) == {}


def test_an_entry_without_a_separator_is_rejected():

    # None, not {} - the callers check for None to abort before touching files.
    assert audiometadata.parse_force_tags(["genre"]) is None


def test_an_unknown_field_is_rejected():
    assert audiometadata.parse_force_tags(["nonsense=x"]) is None


def test_one_bad_entry_rejects_the_whole_set():
    assert audiometadata.parse_force_tags(["genre=Regular", "nonsense=x"]) is None


@pytest.mark.parametrize("field", audiometadata.curated_tag_fields)
def test_every_curated_field_is_accepted(field):
    assert audiometadata.parse_force_tags([f"{field}=value"]) == {field: "value"}
