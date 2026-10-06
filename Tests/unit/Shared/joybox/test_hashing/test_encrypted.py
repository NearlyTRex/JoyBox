# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import hashing
from hashing_helpers import write_file


###########################################################
# Entries for encrypted files
#
# An encrypted file is recorded under the name and digest of what it holds,
# with its on-disk name, digest and size kept in the _enc fields.
###########################################################

EMBEDDED = {"filename": "game.zip", "hash": "plainhash", "size": 5, "mtime": 1234}
TEST_PHRASE = "unit test phrase"


@pytest.fixture
def encrypted_tree(tmp_path, monkeypatch):
    root = tmp_path / "tree"
    write_file(root, os.path.join("Games", "abc.enc"), b"ciphertext")
    embedded = {"info": dict(EMBEDDED)}
    monkeypatch.setattr(hashing.cryption, "is_file_encrypted", lambda path: True)
    monkeypatch.setattr(hashing.cryption, "is_passphrase_valid", lambda phrase: bool(phrase))
    monkeypatch.setattr(hashing.cryption, "get_embedded_file_info",
                        lambda src, passphrase, **kwargs: embedded["info"])
    return str(root), embedded


def test_an_encrypted_file_is_recorded_under_its_embedded_name(encrypted_tree):
    root, _ = encrypted_tree
    data = hashing.calculate_hash(os.path.join("Games", "abc.enc"), base_path = root,
                                  passphrase = TEST_PHRASE)

    assert data["dir"] == "Games"
    assert data["filename"] == "game.zip"
    assert data["filename_enc"] == "abc.enc"
    assert data["hash"] == "plainhash"
    assert data["hash_enc"] == hashing.calculate_file_md5(os.path.join(root, "Games", "abc.enc"))
    assert data["size"] == 5
    assert data["size_enc"] == len(b"ciphertext")
    assert data["mtime"] == 1234


def test_an_encrypted_file_without_a_passphrase_is_hashed_as_it_is(encrypted_tree):
    root, _ = encrypted_tree
    data = hashing.calculate_hash(os.path.join("Games", "abc.enc"), base_path = root)

    assert data["filename"] == "abc.enc"


def test_an_unreadable_encrypted_file_yields_no_entry(encrypted_tree):
    root, embedded = encrypted_tree
    embedded["info"] = None

    assert hashing.calculate_hash(os.path.join("Games", "abc.enc"), base_path = root,
                                  passphrase = TEST_PHRASE) == {}


def test_an_unreadable_encrypted_file_is_left_out_of_the_manifest(encrypted_tree, tmp_path):
    root, embedded = encrypted_tree
    embedded["info"] = None
    output_file = os.path.join(str(tmp_path), "hashes.json")

    assert hashing.hash_files(root, output_file, passphrase = TEST_PHRASE) is True
    assert not os.path.exists(output_file)


###########################################################
# Verbose entries
###########################################################

@pytest.mark.parametrize("pretend_run, message", [
    (True, "[pretend] Would hash file"),
    (False, "Hashing file"),
])
def test_a_verbose_entry_reports_the_file(tmp_path, caplog, pretend_run, message):
    write_file(tmp_path, "one.bin", b"first")
    hashing.calculate_hash("one.bin", base_path = str(tmp_path), verbose = True,
                           pretend_run = pretend_run)

    assert message in caplog.text


def test_a_pretend_entry_can_leave_out_the_encrypted_fields(tmp_path):
    data = hashing.calculate_hash("one.bin", base_path = str(tmp_path), pretend_run = True,
                                  include_enc_fields = False)

    assert "filename_enc" not in data
