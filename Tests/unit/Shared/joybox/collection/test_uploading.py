# Third-party imports
import pytest

# Local imports
from joybox.collection import uploading


###########################################################
# Uploading game files
#
# Game files are encrypted in place before they leave the machine, so a locker
# with no passphrase has to stop the upload rather than send plaintext.
###########################################################

UPLOAD_PHRASE = "upload-phrase"


class FakeGameInfo:

    def get_supercategory(self):
        return "Roms"

    def get_category(self):
        return "Nintendo"

    def get_subcategory(self):
        return "Nintendo NES"

    def get_name(self):
        return "Game"


@pytest.fixture
def upload(monkeypatch, tmp_path):
    state = {"passphrase": UPLOAD_PHRASE, "encrypted": [], "synced": [], "root": tmp_path}
    monkeypatch.setattr(
        uploading.lockerinfo.LockerInfo, "get_passphrase", lambda self: state["passphrase"])

    def encrypt_files(src, passphrase, **kwargs):
        state["encrypted"].append({"src": src, "passphrase": passphrase, **kwargs})
        return [src + "/out.enc"]

    def sync_to_remote(src, **kwargs):
        state["synced"].append(src)
        return True

    monkeypatch.setattr(uploading.cryption, "encrypt_files", encrypt_files)
    monkeypatch.setattr(uploading, "build_hash_files", lambda **kwargs: True)
    monkeypatch.setattr(uploading.locker, "sync_to_remote", sync_to_remote)
    return state


def run_upload(state):
    return uploading.upload_game_files(FakeGameInfo(), game_root = str(state["root"]))


def test_an_upload_encrypts_with_the_locker_passphrase(upload):
    assert run_upload(upload) is True
    assert upload["encrypted"][0]["passphrase"] == UPLOAD_PHRASE
    assert upload["encrypted"][0]["delete_original"] is True
    assert upload["synced"] == [str(upload["root"])]


@pytest.mark.parametrize("passphrase", [None, ""])
def test_an_upload_without_a_passphrase_sends_nothing(upload, passphrase):
    upload["passphrase"] = passphrase

    assert run_upload(upload) is False
    assert upload["encrypted"] == []
    assert upload["synced"] == []
