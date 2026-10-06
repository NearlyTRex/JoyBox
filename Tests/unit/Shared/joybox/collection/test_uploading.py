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


def test_the_default_game_root_is_the_locker_files_dir(upload, monkeypatch):
    asked = []
    monkeypatch.setattr(
        uploading.environment, "get_locker_gaming_files_dir",
        lambda **kwargs: asked.append(kwargs) or str(upload["root"]))

    assert uploading.upload_game_files(FakeGameInfo()) is True
    assert asked[0]["game_name"] == "Game"
    assert upload["synced"] == [str(upload["root"])]


def test_a_missing_game_root_uploads_nothing(upload, monkeypatch):
    monkeypatch.setattr(
        uploading.environment, "get_locker_gaming_files_dir",
        lambda **kwargs: str(upload["root"] / "absent"))

    assert uploading.upload_game_files(FakeGameInfo()) is False
    assert upload["encrypted"] == []


def test_a_failed_encryption_uploads_nothing(upload, monkeypatch):
    monkeypatch.setattr(uploading.cryption, "encrypt_files", lambda **kwargs: [])

    assert run_upload(upload) is False
    assert upload["synced"] == []


def test_a_failed_hash_uploads_nothing(upload, monkeypatch):
    monkeypatch.setattr(uploading, "build_hash_files", lambda **kwargs: False)

    assert run_upload(upload) is False
    assert upload["synced"] == []


def test_the_upload_reports_the_sync_result(upload, monkeypatch):
    monkeypatch.setattr(uploading.locker, "sync_to_remote", lambda **kwargs: False)

    assert run_upload(upload) is False


###########################################################
# Uploading every game
###########################################################

@pytest.fixture
def every_game(monkeypatch):
    state = {"uploaded": [], "result": True}

    class StubGameInfo:
        def __init__(self, game_supercategory, game_category, game_subcategory, game_name, **kwargs):
            self.name = game_name

    def find_json_game_names(game_supercategory, game_category, game_subcategory):
        return ["Alpha", "Beta"] if game_subcategory == uploading.config.Subcategory.NINTENDO_NES else []

    def upload_game_files(game_info, **kwargs):
        state["uploaded"].append(game_info.name)
        return state["result"]

    monkeypatch.setattr(uploading.gameinfo, "GameInfo", StubGameInfo)
    monkeypatch.setattr(uploading.gameinfo, "find_json_game_names", find_json_game_names)
    monkeypatch.setattr(uploading, "upload_game_files", upload_game_files)
    return state


def test_every_game_is_uploaded(every_game):
    assert uploading.upload_all_game_files() is True
    assert every_game["uploaded"] == ["Alpha", "Beta"]


def test_uploading_every_game_stops_at_a_failure(every_game):
    every_game["result"] = False

    assert uploading.upload_all_game_files() is False
    assert every_game["uploaded"] == ["Alpha"]
