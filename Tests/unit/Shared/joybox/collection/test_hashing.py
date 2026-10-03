# Third-party imports
import pytest

# Local imports
from joybox.collection import hashing


###########################################################
# Building hash files
#
# Encrypted game files are hashed through their decrypted contents, so the
# locker passphrase has to reach the hasher.
###########################################################

HASH_PHRASE = "hash-phrase"


class FakeGameInfo:

    def get_supercategory(self):
        return "Roms"

    def get_category(self):
        return "Nintendo"

    def get_subcategory(self):
        return "Nintendo NES"

    def get_name(self):
        return "Game"

    def get_platform(self):
        return "Nintendo NES"


@pytest.fixture
def hashed(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        hashing.lockerinfo.LockerInfo, "get_passphrase", lambda self: HASH_PHRASE)
    monkeypatch.setattr(
        hashing.environment, "get_game_hashes_metadata_file", lambda *args: str(tmp_path / "hashes.json"))
    monkeypatch.setattr(
        hashing.hashing, "hash_files", lambda **kwargs: calls.append(kwargs) or True)
    return calls


def test_hashing_passes_the_locker_passphrase(hashed, tmp_path):
    assert hashing.build_hash_files(FakeGameInfo(), game_root = str(tmp_path)) is True
    assert hashed[0]["passphrase"] == HASH_PHRASE
    assert hashed[0]["src"] == str(tmp_path)
    assert hashed[0]["include_enc_fields"] is True


def test_a_missing_game_root_hashes_nothing(hashed, monkeypatch, tmp_path):
    monkeypatch.setattr(
        hashing.environment, "get_locker_gaming_files_dir", lambda **kwargs: str(tmp_path / "absent"))

    assert hashing.build_hash_files(FakeGameInfo()) is False
    assert hashed == []
