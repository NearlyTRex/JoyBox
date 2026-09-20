# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import cryption

pytestmark = [pytest.mark.requires_tool("Gpg"), pytest.mark.slow]


###########################################################
# Encryption round trips against real gpg
#
# The locker stores these files and nothing else can read them back, so what
# matters is that a file encrypted today decrypts to the same bytes and the
# same name later. A wrapper that reports success without producing a
# readable file loses the data silently.
###########################################################

PASSPHRASE = "example"
WRONG_PASSPHRASE = "dummy"


def write(path, contents = b"payload"):
    path = str(path)
    os.makedirs(os.path.dirname(path), exist_ok = True)
    with open(path, "wb") as handle:
        handle.write(contents)
    return path


@pytest.fixture
def plain_file(tmp_path, requires_tool):
    return write(tmp_path / "Save Game.dat", b"payload" * 1000)


@pytest.fixture
def encrypted_file(tmp_path, plain_file):
    target = str(tmp_path / "stored.enc")
    assert cryption.encrypt_file(
        src = plain_file, passphrase = PASSPHRASE, output_file = target) is True
    return target


###########################################################
# Encrypting
###########################################################

def test_a_file_is_encrypted(plain_file, tmp_path):
    target = str(tmp_path / "stored.enc")

    assert cryption.encrypt_file(
        src = plain_file, passphrase = PASSPHRASE, output_file = target) is True
    assert os.path.isfile(target)


def test_an_encrypted_file_does_not_hold_the_plain_content(encrypted_file):
    # The whole point is that the locker never sees the contents.
    with open(encrypted_file, "rb") as handle:
        assert b"payload" not in handle.read()


def test_an_encrypted_file_is_recognised_as_encrypted(encrypted_file):
    assert cryption.is_file_encrypted(encrypted_file) is True


def test_encrypting_keeps_the_original(plain_file, encrypted_file):
    assert os.path.isfile(plain_file)


def test_encrypting_can_remove_the_original(plain_file, tmp_path):
    target = str(tmp_path / "stored.enc")

    cryption.encrypt_file(
        src = plain_file, passphrase = PASSPHRASE, output_file = target,
        delete_original = True)

    assert not os.path.exists(plain_file)
    assert os.path.isfile(target)


def test_an_existing_destination_is_left_alone(plain_file, tmp_path):
    # Re-encrypting produces different bytes each run, so an existing file is
    # taken as already done rather than rewritten.
    target = write(tmp_path / "stored.enc", b"already here")

    assert cryption.encrypt_file(
        src = plain_file, passphrase = PASSPHRASE, output_file = target) is True
    with open(target, "rb") as handle:
        assert handle.read() == b"already here"


def test_an_already_encrypted_source_is_copied_rather_than_re_encrypted(encrypted_file, tmp_path):
    target = str(tmp_path / "copy.enc")

    assert cryption.encrypt_file(
        src = encrypted_file, passphrase = PASSPHRASE, output_file = target) is True
    with open(target, "rb") as first, open(encrypted_file, "rb") as second:
        assert first.read() == second.read()


def test_encrypting_a_missing_source_reports_failure(tmp_path):
    assert cryption.encrypt_file(
        src = str(tmp_path / "absent.dat"), passphrase = PASSPHRASE,
        output_file = str(tmp_path / "stored.enc")) is False


def test_encrypting_without_a_passphrase_is_refused(plain_file, tmp_path):
    with pytest.raises(AssertionError):
        cryption.encrypt_file(
            src = plain_file, passphrase = "", output_file = str(tmp_path / "stored.enc"))


def test_pretending_encrypts_nothing(plain_file, tmp_path):
    target = str(tmp_path / "stored.enc")

    assert cryption.encrypt_file(
        src = plain_file, passphrase = PASSPHRASE, output_file = target,
        pretend_run = True) is True
    assert not os.path.exists(target)


###########################################################
# Decrypting
###########################################################

def test_an_encrypted_file_decrypts_to_its_original_bytes(encrypted_file, tmp_path):
    target = str(tmp_path / "restored.dat")

    assert cryption.decrypt_file(
        src = encrypted_file, passphrase = PASSPHRASE, output_file = target) is True
    with open(target, "rb") as handle:
        assert handle.read() == b"payload" * 1000


def test_decrypting_with_the_wrong_passphrase_reports_failure(encrypted_file, tmp_path):
    assert cryption.decrypt_file(
        src = encrypted_file, passphrase = WRONG_PASSPHRASE,
        output_file = str(tmp_path / "restored.dat")) is False


def test_a_failed_decryption_leaves_no_usable_file(encrypted_file, tmp_path):
    # A truncated or empty output would look like a restored save.
    target = str(tmp_path / "restored.dat")
    cryption.decrypt_file(
        src = encrypted_file, passphrase = WRONG_PASSPHRASE, output_file = target)

    assert not os.path.exists(target) or os.path.getsize(target) == 0


def test_decrypting_keeps_the_encrypted_copy(encrypted_file, tmp_path):
    cryption.decrypt_file(
        src = encrypted_file, passphrase = PASSPHRASE,
        output_file = str(tmp_path / "restored.dat"))

    assert os.path.isfile(encrypted_file)


def test_decrypting_can_remove_the_encrypted_copy(encrypted_file, tmp_path):
    cryption.decrypt_file(
        src = encrypted_file, passphrase = PASSPHRASE,
        output_file = str(tmp_path / "restored.dat"), delete_original = True)

    assert not os.path.exists(encrypted_file)


def test_a_plain_source_is_copied_rather_than_decrypted(plain_file, tmp_path):
    target = str(tmp_path / "restored.dat")

    assert cryption.decrypt_file(
        src = plain_file, passphrase = PASSPHRASE, output_file = target) is True
    with open(target, "rb") as handle:
        assert handle.read() == b"payload" * 1000


def test_decrypting_a_missing_source_reports_failure(tmp_path):
    assert cryption.decrypt_file(
        src = str(tmp_path / "absent.enc"), passphrase = PASSPHRASE,
        output_file = str(tmp_path / "restored.dat")) is False


###########################################################
# Recovering the original name
#
# The stored name is a hash, so the only record of what a file was called is
# the one gpg carries inside it.
###########################################################

def test_the_original_filename_survives_encryption(encrypted_file):
    assert cryption.get_embedded_filename(
        src = encrypted_file, passphrase = PASSPHRASE) == "Save Game.dat"


def test_a_name_with_spaces_and_punctuation_survives(tmp_path):
    source = write(tmp_path / "Game (USA) [v1.1] - Disc 1.iso", b"data")
    target = str(tmp_path / "stored.enc")
    cryption.encrypt_file(src = source, passphrase = PASSPHRASE, output_file = target)

    assert cryption.get_embedded_filename(src = target, passphrase = PASSPHRASE) == \
        "Game (USA) [v1.1] - Disc 1.iso"


def test_the_real_path_puts_the_name_back_beside_the_stored_file(encrypted_file, tmp_path):
    assert cryption.get_real_file_path(src = encrypted_file, passphrase = PASSPHRASE) == \
        os.path.join(str(tmp_path), "Save Game.dat")


def test_a_plain_file_is_already_its_real_path(plain_file):
    assert cryption.get_real_file_path(src = plain_file, passphrase = PASSPHRASE) == plain_file


def test_several_stored_files_resolve_to_their_own_names(tmp_path):
    first = write(tmp_path / "First.dat", b"one")
    second = write(tmp_path / "Second.dat", b"two")
    stored = []
    for index, source in enumerate([first, second]):
        target = str(tmp_path / ("stored%d.enc" % index))
        cryption.encrypt_file(src = source, passphrase = PASSPHRASE, output_file = target)
        stored.append(target)

    resolved = cryption.get_real_file_paths(src = stored, passphrase = PASSPHRASE)

    assert sorted(os.path.basename(path) for path in resolved) == ["First.dat", "Second.dat"]


###########################################################
# Whole directories
###########################################################

def test_every_file_in_a_tree_is_encrypted(tmp_path):
    source = tmp_path / "saves"
    write(source / "one.dat", b"one")
    write(source / "nested" / "two.dat", b"two")

    produced = cryption.encrypt_files(src = str(source), passphrase = PASSPHRASE)

    assert len(produced) == 2
    assert all(os.path.isfile(path) for path in produced)
    assert all(cryption.is_file_encrypted(path) for path in produced)


def test_an_encrypted_tree_decrypts_back_to_its_names(tmp_path):
    source = tmp_path / "saves"
    write(source / "one.dat", b"one")
    cryption.encrypt_files(src = str(source), passphrase = PASSPHRASE, delete_original = True)

    produced = cryption.decrypt_files(src = str(source), passphrase = PASSPHRASE)

    assert [os.path.basename(path) for path in produced] == ["one.dat"]
    with open(produced[0], "rb") as handle:
        assert handle.read() == b"one"
