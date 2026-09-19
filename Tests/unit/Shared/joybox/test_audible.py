# Imports
import os
import pytest

# Local imports
from joybox import audible


###########################################################
# Activation bytes
#
# The 8 hex character key that decrypts an AAX audiobook. It is pulled out of
# whatever the user pasted or saved, so the extraction has to find it inside
# surrounding text and refuse anything that is not exactly eight hex digits.
###########################################################

def test_bare_activation_bytes_are_extracted():
    assert audible.extract_activation_bytes("1a2b3c4d") == "1a2b3c4d"


def test_uppercase_activation_bytes_are_extracted():
    assert audible.extract_activation_bytes("1A2B3C4D") == "1A2B3C4D"


def test_case_is_preserved():
    # ffmpeg takes the value verbatim.
    assert audible.extract_activation_bytes("AbCdEf01") == "AbCdEf01"


def test_digits_only_are_extracted():
    assert audible.extract_activation_bytes("12345678") == "12345678"


def test_letters_only_are_extracted():
    assert audible.extract_activation_bytes("abcdefab") == "abcdefab"


###########################################################
# Surrounding text
###########################################################

@pytest.mark.parametrize("text", [
    "1a2b3c4d\n",
    "  1a2b3c4d  ",
    "activation_bytes: 1a2b3c4d",
    "Your activation bytes are 1a2b3c4d, keep them safe.",
    "1a2b3c4d is the key",
    "key=1a2b3c4d",
    "[1a2b3c4d]",
    "line one\n1a2b3c4d\nline three",
])
def test_activation_bytes_are_found_in_surrounding_text(text):
    assert audible.extract_activation_bytes(text) == "1a2b3c4d"


def test_the_first_match_wins():
    assert audible.extract_activation_bytes("1a2b3c4d and deadbeef") == "1a2b3c4d"


###########################################################
# Rejected input
###########################################################

@pytest.mark.parametrize("text", [
    None,
    "",
    "   ",
    "no key here",
    "1a2b3c",
    "1a2b3c4",
    "xxxxxxxx",
    "1a2b3c4g",
    "the quick brown fox",
])
def test_input_without_activation_bytes_yields_nothing(text):
    assert audible.extract_activation_bytes(text) is None


def test_a_longer_hex_run_is_not_a_match():
    # A nine digit run is not a key, and taking eight of it would hand ffmpeg a
    # silently truncated value.
    assert audible.extract_activation_bytes("1a2b3c4d5") is None


def test_a_longer_hex_run_beside_a_real_key_does_not_win():
    assert audible.extract_activation_bytes("1a2b3c4d5e 1a2b3c4d") == "1a2b3c4d"


def test_a_hex_run_inside_a_word_is_not_a_match():
    assert audible.extract_activation_bytes("prefix1a2b3c4dsuffix") is None


@pytest.mark.parametrize("separator", ["-", ":", "/", "."])
def test_a_key_bounded_by_punctuation_is_found(separator):
    assert audible.extract_activation_bytes(
        "key%s1a2b3c4d%send" % (separator, separator)) == "1a2b3c4d"


###########################################################
# Lookup order
###########################################################

@pytest.fixture
def no_ambient_sources(monkeypatch, tmp_path):
    # An unrelated key in the user's real settings, environment or home
    # directory would otherwise decide these.
    monkeypatch.setattr(audible.settings, "get_value", lambda *args, **kwargs: None)
    monkeypatch.delenv("AUDIBLE_ACTIVATION_BYTES", raising = False)
    monkeypatch.setattr(audible.runtime, "get_home_directory", lambda: str(tmp_path))
    return tmp_path


def test_the_settings_value_is_preferred(monkeypatch, no_ambient_sources):
    monkeypatch.setattr(audible.settings, "get_value", lambda *args, **kwargs: "1a2b3c4d")
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.get_activation_bytes() == "1a2b3c4d"


def test_an_authcode_file_is_read(no_ambient_sources, tmp_path):
    target = tmp_path / "authcode.txt"
    target.write_text("activation_bytes: 1a2b3c4d\n")

    assert audible.get_activation_bytes(str(target)) == "1a2b3c4d"


def test_an_authcode_file_beats_the_environment(monkeypatch, no_ambient_sources, tmp_path):
    target = tmp_path / "authcode.txt"
    target.write_text("1a2b3c4d")
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.get_activation_bytes(str(target)) == "1a2b3c4d"


def test_the_environment_is_used_when_nothing_else_has_a_key(monkeypatch, no_ambient_sources):
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.get_activation_bytes() == "deadbeef"


def test_the_home_directory_file_is_the_last_resort(no_ambient_sources, tmp_path):
    (tmp_path / ".audible_authcode").write_text("1a2b3c4d\n")

    assert audible.get_activation_bytes() == "1a2b3c4d"


def test_a_missing_authcode_file_falls_through(monkeypatch, no_ambient_sources, tmp_path):
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.get_activation_bytes(str(tmp_path / "absent.txt")) == "deadbeef"


def test_a_source_holding_no_key_falls_through(monkeypatch, no_ambient_sources, tmp_path):
    # An empty or placeholder file must not stop the search.
    target = tmp_path / "authcode.txt"
    target.write_text("paste your key here\n")
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.get_activation_bytes(str(target)) == "deadbeef"


def test_no_source_yields_nothing(no_ambient_sources):
    assert audible.get_activation_bytes() is None
