# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.collection import purchase
from purchase_helpers import FakeStore


###########################################################
# Downloading a purchase
###########################################################

class FakeGameInfo:

    def __init__(self, name = "Half-Life 2", platform = "Computer"):
        self.name = name
        self.platform = platform

    def get_name(self):
        return self.name

    def get_platform(self):
        return self.platform

    def get_supercategory(self):
        return config.Supercategory.ROMS

    def get_category(self):
        return config.Category.COMPUTER

    def get_subcategory(self):
        return config.subcategory_map[config.Category.COMPUTER][0]

    def get_store_info_identifier(self):
        return "220"

    def get_store_download_identifier(self):
        return "220"

    def get_store_branchid(self):
        return None


@pytest.fixture
def downloads(monkeypatch, tmp_path):
    state = {"store": FakeStore(), "contains_files": False}

    monkeypatch.setattr(
        purchase.stores, "get_store_by_platform", lambda platform: state["store"])
    monkeypatch.setattr(
        purchase.environment, "get_locker_gaming_files_dir",
        lambda **kwargs: str(tmp_path / "locker" / "Half-Life 2"))
    monkeypatch.setattr(
        purchase.environment, "get_locker_gaming_files_offset",
        lambda **kwargs: "Computer/Half-Life 2")
    monkeypatch.setattr(
        purchase.paths, "does_directory_contain_files",
        lambda path: state["contains_files"])
    return state


def test_a_purchase_is_downloaded_into_the_locker(downloads, tmp_path):
    assert purchase.download_game_store_purchase(FakeGameInfo()) is True

    assert downloads["store"].downloads[0]["output_dir"] == \
        str(tmp_path / "locker" / "Half-Life 2")


def test_a_download_is_named_with_its_version(downloads):
    # The version in the name is how a later run notices an update.
    downloads["store"] = FakeStore(latest_version = "2.5")

    purchase.download_game_store_purchase(FakeGameInfo())

    assert downloads["store"].downloads[0]["output_name"] == "Half-Life 2 (2.5)"


def test_a_download_can_be_redirected_outside_the_locker(downloads, tmp_path):
    target = tmp_path / "staging"
    target.mkdir()

    purchase.download_game_store_purchase(FakeGameInfo(), output_dir = str(target))

    assert downloads["store"].downloads[0]["output_dir"].startswith(str(target))


def test_a_redirected_download_keeps_its_collection_layout(downloads, tmp_path):
    target = tmp_path / "staging"
    target.mkdir()

    purchase.download_game_store_purchase(FakeGameInfo(), output_dir = str(target))

    assert downloads["store"].downloads[0]["output_dir"].endswith("Half-Life 2")


def test_a_game_whose_platform_has_no_store_is_not_downloaded(downloads):
    downloads["store"] = None

    assert purchase.download_game_store_purchase(FakeGameInfo()) is False


def test_a_store_that_cannot_download_is_skipped(downloads):
    downloads["store"] = FakeStore(can_download = False)

    assert purchase.download_game_store_purchase(FakeGameInfo()) is True
    assert downloads["store"].downloads == []


def test_an_already_downloaded_purchase_can_be_skipped(downloads):
    # Re-downloading a game is tens of gigabytes.
    downloads["contains_files"] = True

    assert purchase.download_game_store_purchase(
        FakeGameInfo(), skip_existing = True) is True
    assert downloads["store"].downloads == []


def test_an_existing_download_is_replaced_by_default(downloads):
    downloads["contains_files"] = True

    purchase.download_game_store_purchase(FakeGameInfo())

    assert len(downloads["store"].downloads) == 1


def test_a_download_clears_what_was_there_before(downloads):
    # A partial previous download left in place would be mixed with the new.
    purchase.download_game_store_purchase(FakeGameInfo())

    assert downloads["store"].downloads[0]["clean_output"] is True


###########################################################
# Downloading every purchase
###########################################################

@pytest.fixture
def all_downloads(monkeypatch):
    state = {"names": ["Half-Life 2"], "downloaded": [], "ok": True}

    monkeypatch.setattr(
        purchase.gameinfo, "find_json_game_names",
        lambda supercategory, category, subcategory: (
            state["names"] if category == config.Category.COMPUTER else []))
    monkeypatch.setattr(
        purchase.gameinfo, "GameInfo",
        lambda **kwargs: FakeGameInfo(name = kwargs["game_name"]))

    def download_game_store_purchase(game_info, **kwargs):
        state["downloaded"].append(game_info.get_name())
        return state["ok"]

    monkeypatch.setattr(purchase, "download_game_store_purchase", download_game_store_purchase)
    return state


def test_every_game_in_the_collection_is_downloaded(all_downloads):
    all_downloads["names"] = ["Half-Life 2", "Portal"]

    assert purchase.download_all_game_store_purchases() is True
    subcategories = len(config.subcategory_map[config.Category.COMPUTER])
    assert all_downloads["downloaded"] == ["Half-Life 2", "Portal"] * subcategories


def test_downloading_everything_stops_at_the_first_failure(all_downloads):
    all_downloads["ok"] = False

    assert purchase.download_all_game_store_purchases() is False
    assert all_downloads["downloaded"] == ["Half-Life 2"]
