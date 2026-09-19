# Imports
import pytest

# Local imports
from joybox import config, cryption, hashutil


###########################################################
# Encrypted naming
#
# The encrypted name is what lands on the remote locker, so it has to be
# derived only from the original filename - a path-dependent name would change
# when the same file is synced from a different directory.
###########################################################

@pytest.mark.parametrize("extension", config.EncryptedFileType.cvalues())
def test_an_encrypted_extension_is_recognised(extension):
    assert cryption.is_file_encrypted(f"game{extension}") is True


def test_a_plain_file_is_not_encrypted():
    assert cryption.is_file_encrypted("game.iso") is False
    assert cryption.is_file_encrypted("game") is False


def test_an_encrypted_name_is_the_hash_of_the_filename():
    expected = hashutil.calculate_string_md5("game.iso") + config.EncryptedFileType.ENC.cval()

    assert cryption.generate_encrypted_filename("game.iso") == expected


def test_an_encrypted_name_is_deterministic():
    assert cryption.generate_encrypted_filename("game.iso") == \
        cryption.generate_encrypted_filename("game.iso")


def test_different_files_get_different_names():
    assert cryption.generate_encrypted_filename("one.iso") != \
        cryption.generate_encrypted_filename("two.iso")


def test_an_already_encrypted_name_passes_through():
    # Re-encrypting must not hash the hash.
    assert cryption.generate_encrypted_filename("abc123.enc") == "abc123.enc"


def test_an_encrypted_name_carries_the_encrypted_extension():
    assert cryption.generate_encrypted_filename("game.iso").endswith(
        config.EncryptedFileType.ENC.cval())


def test_an_encrypted_name_hides_the_original():
    assert "game" not in cryption.generate_encrypted_filename("game.iso")


###########################################################
# Encrypted paths
###########################################################

def test_an_encrypted_path_keeps_the_directory():
    assert cryption.generate_encrypted_path("a/b/game.iso").startswith("a/b/")


def test_an_encrypted_path_hashes_only_the_filename():
    # The same file in two directories has to encrypt to the same name, or a
    # move would look like a different file to the locker.
    first = cryption.generate_encrypted_path("a/game.iso")
    second = cryption.generate_encrypted_path("b/c/game.iso")

    assert first.split("/")[-1] == second.split("/")[-1]


def test_an_encrypted_path_for_a_bare_filename_has_no_directory():
    assert "/" not in cryption.generate_encrypted_path("game.iso")


###########################################################
# Passphrases
###########################################################

def test_a_non_empty_string_is_a_valid_passphrase():
    assert cryption.is_passphrase_valid("hunter2") is True


@pytest.mark.parametrize("candidate", ["", None, 123, [], b"bytes"])
def test_anything_else_is_not_a_valid_passphrase(candidate):
    assert cryption.is_passphrase_valid(candidate) is False
