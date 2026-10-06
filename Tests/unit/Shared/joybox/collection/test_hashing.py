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


def test_the_default_game_root_is_the_locker_files_dir(hashed, monkeypatch, tmp_path):
    asked = []
    monkeypatch.setattr(
        hashing.environment, "get_locker_gaming_files_dir",
        lambda **kwargs: asked.append(kwargs) or str(tmp_path))

    assert hashing.build_hash_files(FakeGameInfo()) is True
    assert asked[0]["game_name"] == "Game"
    assert hashed[0]["offset"].endswith("Game")


###########################################################
# Hash file upkeep
###########################################################

@pytest.fixture
def hash_files(monkeypatch, tmp_path):
    # Only the NES hash file exists.
    state = {"calls": [], "result": True}
    present = str(tmp_path / "Nintendo NES.json")
    open(present, "w").close()

    def get_game_hashes_metadata_file(game_supercategory, game_category, game_subcategory):
        if game_subcategory == "Nintendo NES":
            return present
        return str(tmp_path / "absent.json")

    def record(name):
        return lambda **kwargs: state["calls"].append((name, kwargs)) or state["result"]

    monkeypatch.setattr(hashing.environment, "get_game_hashes_metadata_file", get_game_hashes_metadata_file)
    monkeypatch.setattr(hashing.hashing, "clean_missing_hash_entries", record("clean"))
    monkeypatch.setattr(hashing.hashing, "sort_hash_file", record("sort"))
    state["present"] = present
    return state


def test_cleaning_an_existing_hash_file_uses_the_locker_root(hash_files):
    assert hashing.clean_missing_hash_entries("Roms", "Nintendo", "Nintendo NES", "/locker") is True
    assert hash_files["calls"][0][1]["hash_file"] == hash_files["present"]
    assert hash_files["calls"][0][1]["locker_root"] == "/locker"


def test_cleaning_without_a_hash_file_has_nothing_to_do(hash_files):
    assert hashing.clean_missing_hash_entries("Roms", "Nintendo", "Nintendo SNES", "/locker") is True
    assert hash_files["calls"] == []


class SubcategoryGameInfo(FakeGameInfo):

    def __init__(self, subcategory):
        self.subcategory = subcategory

    def get_subcategory(self):
        return self.subcategory


def test_sorting_a_game_sorts_its_hash_file(hash_files):
    assert hashing.sort_hash_file(SubcategoryGameInfo("Nintendo NES")) is True
    assert hash_files["calls"] == [("sort", {"src": hash_files["present"], "verbose": False,
                                            "pretend_run": False, "exit_on_failure": False})]


def test_sorting_a_game_without_a_hash_file_fails(hash_files):
    assert hashing.sort_hash_file(SubcategoryGameInfo("Nintendo SNES")) is False


def test_sorting_everything_visits_only_existing_hash_files(hash_files):
    assert hashing.sort_all_hash_files() is True
    assert [kwargs["src"] for name, kwargs in hash_files["calls"]] == [hash_files["present"]] * len(hashing.config.Supercategory.members())


def test_sorting_everything_stops_at_a_failure(hash_files):
    hash_files["result"] = False

    assert hashing.sort_all_hash_files() is False
    assert len(hash_files["calls"]) == 1


###########################################################
# Hashing every game
###########################################################

@pytest.fixture
def every_game(monkeypatch):
    state = {"built": [], "result": True}

    class StubGameInfo:
        def __init__(self, game_supercategory, game_category, game_subcategory, game_name, **kwargs):
            self.name = game_name

    def find_json_game_names(game_supercategory, game_category, game_subcategory):
        return ["Alpha", "Beta"] if game_subcategory == hashing.config.Subcategory.NINTENDO_NES else []

    def build_hash_files(game_info, **kwargs):
        state["built"].append(game_info.name)
        return state["result"]

    monkeypatch.setattr(hashing.gameinfo, "GameInfo", StubGameInfo)
    monkeypatch.setattr(hashing.gameinfo, "find_json_game_names", find_json_game_names)
    monkeypatch.setattr(hashing, "build_hash_files", build_hash_files)
    return state


def test_every_game_is_hashed(every_game):
    assert hashing.build_all_hash_files() is True
    assert every_game["built"] == ["Alpha", "Beta"]


def test_hashing_every_game_stops_at_a_failure(every_game):
    every_game["result"] = False

    assert hashing.build_all_hash_files() is False
    assert every_game["built"] == ["Alpha"]
