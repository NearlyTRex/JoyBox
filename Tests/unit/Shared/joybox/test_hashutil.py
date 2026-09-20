# Imports
import pytest

# Local imports
from joybox import hashutil


###########################################################
# String hashing
#
# Published vectors rather than recomputing with hashlib in the test, which
# would only assert that the function calls the library it obviously calls.
# These pin the encoding and the output format, which is where the real risk is:
# a switch to utf-16, or to uppercase hex, silently invalidates every stored
# hash in a collection.
###########################################################

HELLO_VECTORS = {
    "crc32": "3610a686",
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
}

EMPTY_VECTORS = {
    "crc32": "00000000",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


def hasher(algorithm):
    return getattr(hashutil, f"calculate_string_{algorithm}")


@pytest.mark.parametrize("algorithm,expected", sorted(HELLO_VECTORS.items()))
def test_known_vectors(algorithm, expected):
    assert hasher(algorithm)("hello") == expected


@pytest.mark.parametrize("algorithm,expected", sorted(EMPTY_VECTORS.items()))
def test_empty_string_vectors(algorithm, expected):
    assert hasher(algorithm)("") == expected


@pytest.mark.parametrize("algorithm", sorted(HELLO_VECTORS))
def test_bytes_and_text_agree(algorithm):
    # The functions encode str themselves, so passing bytes in must land on the
    # same digest rather than double-encoding.
    assert hasher(algorithm)("hello") == hasher(algorithm)(b"hello")


@pytest.mark.parametrize("algorithm", sorted(HELLO_VECTORS))
def test_output_is_lowercase_hex(algorithm):
    digest = hasher(algorithm)("some content")

    assert digest == digest.lower()
    assert all(character in "0123456789abcdef" for character in digest)


def test_non_ascii_is_encoded_as_utf8():
    # Pins the encoding explicitly: a latin-1 or utf-16 fallback would produce a
    # different digest for the same file name.
    assert hashutil.calculate_string_md5("café") == "07117fe4a1ebd544965dc19573183da2"


@pytest.mark.parametrize("algorithm", sorted(HELLO_VECTORS))
def test_different_inputs_produce_different_digests(algorithm):
    assert hasher(algorithm)("a") != hasher(algorithm)("b")


def test_xxh3_is_stable():
    pytest.importorskip("xxhash")
    assert hashutil.calculate_string_xxh3(b"hello") == "9555e8555c62dcfd"
