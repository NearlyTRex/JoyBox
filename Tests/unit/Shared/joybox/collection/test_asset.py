# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.collection import asset


###########################################################
# Downloading metadata assets
#
# Finds an asset url for a game (from its store, or by searching), downloads,
# converts and cleans it in a temporary directory, then backs it up to the
# lockers. The temporary directory must not outlive the call.
###########################################################

class FakeGameInfo:

    def __init__(self, name = "Half-Life 2", platform = "Computer - Steam"):
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

    def get_store_asset_identifier(self):
        return "220"


class FakeStore:

    def __init__(self, url = "https://store.example/boxfront.jpg"):
        self.url = url
        self.asked = []

    def get_latest_asset_url(self, identifier, asset_type, game_name, **kwargs):
        self.asked.append((identifier, asset_type, game_name))
        return self.url


@pytest.fixture
def assets(monkeypatch, tmp_path):
    state = {
        "existing": set(),
        "tmp_ok": True,
        "store": FakeStore(),
        "searched_url": "https://search.example/found.jpg",
        "searched": [],
        "reachable": True,
        "download_ok": True,
        "convert_ok": True,
        "clean_ok": True,
        "backup_ok": True,
        "steps": [],
        "made_dirs": [],
        "removed": [],
        "backups": [],
    }
    tmp_dir = str(tmp_path / "tmp")

    monkeypatch.setattr(
        asset.environment, "get_locker_gaming_asset_file",
        lambda game_category, game_subcategory, game_name, asset_type: (
            "/locker/Assets/%s/%s%s" % (asset_type, game_name, asset_type.cval())))
    monkeypatch.setattr(
        asset.environment, "get_locker_gaming_asset_dir",
        lambda game_category, game_subcategory, asset_type: "/locker/Assets/%s" % asset_type)
    monkeypatch.setattr(
        asset.paths, "does_path_exist", lambda path: path in state["existing"])
    monkeypatch.setattr(
        asset.fileops, "create_temporary_directory",
        lambda **kwargs: (state["tmp_ok"], tmp_dir))
    monkeypatch.setattr(
        asset.stores, "get_store_by_platform", lambda store_platform, **kwargs: state["store"])

    def find_metadata_asset(game_platform, game_name, asset_type, **kwargs):
        state["searched"].append((game_platform, game_name, asset_type))
        return state["searched_url"]

    def step(name, key):
        def run(**kwargs):
            state["steps"].append((name, kwargs))
            return state[key]
        return run

    monkeypatch.setattr(asset.metadataassetcollector, "find_metadata_asset", find_metadata_asset)
    monkeypatch.setattr(asset.network, "is_url_reachable", lambda url: bool(url) and state["reachable"])
    monkeypatch.setattr(
        asset.fileops, "make_directory",
        lambda src, **kwargs: state["made_dirs"].append(src) or True)
    monkeypatch.setattr(asset.asset, "download_asset", step("download", "download_ok"))
    monkeypatch.setattr(asset.asset, "convert_asset", step("convert", "convert_ok"))
    monkeypatch.setattr(asset.asset, "clean_asset", step("clean", "clean_ok"))
    monkeypatch.setattr(
        asset.locker, "convert_to_relative_path", lambda path: path.replace("/locker/", ""))

    def backup(**kwargs):
        state["backups"].append(kwargs)
        return state["backup_ok"]

    monkeypatch.setattr(asset.locker, "backup", backup)
    monkeypatch.setattr(
        asset.fileops, "remove_directory",
        lambda src, **kwargs: state["removed"].append(src) or True)
    monkeypatch.setattr(asset.logger, "log_error", lambda *args, **kwargs: None)
    state["tmp_dir"] = tmp_dir
    return state


def download(**kwargs):
    defaults = dict(game_info = FakeGameInfo(), asset_type = config.AssetType.BOXFRONT)
    defaults.update(kwargs)
    return asset.download_metadata_asset(**defaults)


###########################################################
# Existence
###########################################################

def test_an_asset_in_the_locker_exists(assets):
    assets["existing"].add("/locker/Assets/BoxFront/Half-Life 2.jpg")

    assert asset.does_metadata_asset_exist(FakeGameInfo(), config.AssetType.BOXFRONT) is True


def test_an_asset_not_in_the_locker_does_not_exist(assets):
    assert asset.does_metadata_asset_exist(FakeGameInfo(), config.AssetType.VIDEO) is False


###########################################################
# Downloading one asset
###########################################################

def test_an_existing_asset_can_be_skipped(assets):
    assets["existing"].add("/locker/Assets/BoxFront/Half-Life 2.jpg")

    assert download(skip_existing = True) is True
    assert assets["steps"] == []


def test_an_existing_asset_is_replaced_by_default(assets):
    assets["existing"].add("/locker/Assets/BoxFront/Half-Life 2.jpg")

    assert download() is True
    assert len(assets["backups"]) == 1


def test_a_failed_temporary_directory_stops_the_download(assets):
    assets["tmp_ok"] = False

    assert download() is False
    assert assets["steps"] == []
    assert assets["removed"] == []


def test_a_store_game_asks_its_store_for_the_url(assets):
    assert download() is True
    assert assets["store"].asked == [("220", config.AssetType.BOXFRONT, "Half-Life 2")]
    assert assets["searched"] == []
    assert assets["steps"][0][1]["asset_url"] == "https://store.example/boxfront.jpg"


def test_a_game_without_a_store_is_searched_for(assets):
    assets["store"] = None

    assert download() is True
    assert assets["searched"] == [("Computer - Steam", "Half-Life 2", config.AssetType.BOXFRONT)]
    assert assets["steps"][0][1]["asset_url"] == "https://search.example/found.jpg"


def test_an_asset_passes_through_download_convert_and_clean(assets):
    assert download() is True

    original = assets["tmp_dir"] + "/boxfront.jpg"
    converted = original + ".jpg"
    assert [name for name, _ in assets["steps"]] == ["download", "convert", "clean"]
    assert assets["steps"][0][1]["asset_file"] == original
    assert assets["steps"][1][1]["asset_src"] == original
    assert assets["steps"][1][1]["asset_dest"] == converted
    assert assets["steps"][2][1]["asset_file"] == converted


def test_an_asset_is_backed_up_to_its_locker_path(assets):
    assert download(locker_type = config.LockerType.ALL, skip_existing = False) is True

    backup = assets["backups"][0]
    assert backup["src"] == assets["tmp_dir"] + "/boxfront.jpg.jpg"
    assert backup["dest_rel_path"] == "Assets/BoxFront/Half-Life 2.jpg"
    assert backup["locker_type"] == config.LockerType.ALL
    assert assets["made_dirs"] == ["/locker/Assets/BoxFront"]


def test_a_successful_download_removes_the_temporary_directory(assets):
    assert download() is True
    assert assets["removed"] == [assets["tmp_dir"]]


@pytest.mark.parametrize("failure", [
    "unreachable", "download_ok", "convert_ok", "clean_ok", "backup_ok",
])
def test_a_failed_step_fails_and_removes_the_temporary_directory(assets, failure):
    if failure == "unreachable":
        assets["reachable"] = False
    else:
        assets[failure] = False

    assert download() is False
    assert assets["removed"] == [assets["tmp_dir"]]


def test_no_url_found_downloads_nothing(assets):
    assets["store"] = FakeStore(url = None)

    assert download() is False
    assert assets["steps"] == []


def test_a_failed_download_is_not_converted(assets):
    assets["download_ok"] = False

    download()

    assert [name for name, _ in assets["steps"]] == ["download"]
    assert assets["backups"] == []


###########################################################
# Downloading every asset
###########################################################

@pytest.fixture
def all_assets(monkeypatch):
    state = {"names": ["Half-Life 2"], "downloaded": [], "ok": True}

    monkeypatch.setattr(
        asset.gameinfo, "find_json_game_names",
        lambda supercategory, category, subcategory: (
            state["names"] if category == config.Category.COMPUTER else []))
    monkeypatch.setattr(
        asset.gameinfo, "GameInfo",
        lambda **kwargs: FakeGameInfo(name = kwargs["game_name"]))

    def download_metadata_asset(game_info, asset_type, skip_existing, **kwargs):
        state["downloaded"].append((
            game_info.get_name(), asset_type, skip_existing,
            game_info.get_subcategory()))
        return state["ok"]

    monkeypatch.setattr(asset, "download_metadata_asset", download_metadata_asset)
    return state


def test_every_game_gets_every_minimum_asset(all_assets):
    assert asset.download_all_metadata_assets(skip_existing = True) is True

    subcategories = len(config.subcategory_map[config.Category.COMPUTER])
    expected = len(config.AssetMinType.members()) * subcategories
    assert len(all_assets["downloaded"]) == expected
    assert {entry[1] for entry in all_assets["downloaded"]} == set(config.AssetMinType.members())
    assert all(entry[2] is True for entry in all_assets["downloaded"])


def test_every_asset_can_be_limited_to_categories(all_assets):
    assert asset.download_all_metadata_assets(categories = [config.Category.NINTENDO]) is True
    assert all_assets["downloaded"] == []


def test_every_asset_can_be_limited_to_subcategories(all_assets):
    subcategory = config.subcategory_map[config.Category.COMPUTER][0]

    assert asset.download_all_metadata_assets(subcategories = [subcategory]) is True
    assert len(all_assets["downloaded"]) == len(config.AssetMinType.members())


def test_downloading_every_asset_stops_at_the_first_failure(all_assets):
    all_assets["ok"] = False

    assert asset.download_all_metadata_assets() is False
    assert len(all_assets["downloaded"]) == 1
