# Imports
import json
import os
import time

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import gog


###########################################################
# Purchases
#
# LGOGDownloader writes its game list to the stdout file it is given; the fake
# runner writes the listing there so the read is real.
###########################################################

LISTING = [
    {"gamename": "the_witcher", "product_id": 1207658924, "title": "The Witcher"},
    {"gamename": "fallout", "product_id": 1207658932, "title": "Fallout"},
]


@pytest.fixture
def listing(gog_store, tools, temp_dir, monkeypatch, tmp_path):
    state = {"json": LISTING, "code": 0, "calls": []}
    monkeypatch.setattr(gog_store, "get_purchases_cache_dir", lambda: str(tmp_path / "cache"))

    def run_returncode_command(cmd, options = None, **kwargs):
        state["calls"].append((list(cmd), options))
        if state["json"] is not None:
            with open(options.get_stdout(), "w") as handle:
                handle.write(json.dumps(state["json"]))
        return state["code"]
    monkeypatch.setattr(gog.command, "run_returncode_command", run_returncode_command)
    state["cache"] = tmp_path / "cache" / "gog_purchases_cache.json"
    return state


def appids(purchases):
    return [purchase.get_value(config.json_key_store_appid) for purchase in purchases]


def test_listed_games_become_purchases(gog_store, listing, temp_dir):
    purchases = gog_store.get_latest_purchases()

    assert appids(purchases) == ["1207658924", "1207658932"]
    first = purchases[0]
    assert first.get_value(config.json_key_store_appname) == "the_witcher"
    assert first.get_value(config.json_key_store_name) == "The Witcher"
    assert first.get_value(config.json_key_store_appurl) == "https://www.gog.com/en/game/the_witcher"
    assert listing["calls"][0][0] == ["/tools/lgogdownloader", "--list", "j"]
    assert listing["calls"][0][1].get_stdout() == str(temp_dir["path"] / "manifest.json")


def test_the_listing_temp_is_removed(gog_store, listing, temp_dir):
    gog_store.get_latest_purchases()

    assert not temp_dir["path"].exists()


@pytest.mark.parametrize("verbose", [True, False])
def test_purchases_are_cached_for_a_day(gog_store, listing, temp_dir, verbose):
    gog_store.get_latest_purchases(verbose = verbose)
    listing["json"] = [{"gamename": "other", "product_id": 1, "title": "Other"}]

    again = gog_store.get_latest_purchases(verbose = verbose)

    assert len(listing["calls"]) == 1
    assert appids(again) == ["1207658924", "1207658932"]
    assert json.loads(listing["cache"].read_text()) == LISTING


def test_a_stale_cache_is_refreshed(gog_store, listing, temp_dir):
    gog_store.get_latest_purchases()
    day_ago = time.time() - 25 * 3600
    os.utime(listing["cache"], (day_ago, day_ago))

    gog_store.get_latest_purchases()

    assert len(listing["calls"]) == 2


@pytest.mark.parametrize("verbose", [True, False])
@pytest.mark.parametrize("cached", [{"not": "a list"}, ["not a dict"]])
def test_an_unusable_cache_is_refetched(gog_store, listing, cached, verbose):
    listing["cache"].parent.mkdir(parents = True)
    listing["cache"].write_text(json.dumps(cached))

    assert appids(gog_store.get_latest_purchases(verbose = verbose)) == ["1207658924", "1207658932"]
    assert len(listing["calls"]) == 1


def test_an_empty_library_is_cached(gog_store, listing, temp_dir):
    listing["json"] = []
    assert gog_store.get_latest_purchases() == []

    assert gog_store.get_latest_purchases() == []
    assert len(listing["calls"]) == 1


def test_a_failed_listing_gives_no_purchases(gog_store, listing, temp_dir):
    listing["code"] = 1

    assert gog_store.get_latest_purchases() is None
    assert not temp_dir["path"].exists()
    assert not listing["cache"].exists()


@pytest.mark.parametrize("listed", [None, {"not": "a list"}, ["not a dict"]])
def test_an_unreadable_listing_gives_no_purchases(gog_store, listing, temp_dir, listed):
    listing["json"] = listed

    assert gog_store.get_latest_purchases() is None
    assert not temp_dir["path"].exists()
    assert not listing["cache"].exists()


def test_purchases_need_lgogdownloader(gog_store, listing, tools):
    del tools["programs"]["LGOGDownloader"]

    assert gog_store.get_latest_purchases() is None
    assert listing["calls"] == []


def test_purchases_need_a_temp_directory(gog_store, listing, temp_dir):
    temp_dir["ok"] = False

    assert gog_store.get_latest_purchases() is None
    assert listing["calls"] == []


def test_a_failed_cache_write_still_returns_purchases(gog_store, listing, monkeypatch):
    monkeypatch.setattr(gog.serialization, "write_json_file", lambda **kwargs: False)

    assert len(gog_store.get_latest_purchases(verbose = True)) == 2


###########################################################
# Product info
###########################################################

PRODUCT = {
    "id": 1207658924,
    "title": " The Witcher ",
    "slug": "the_witcher",
    "links": {"product_card": "https://www.gog.com/game/the_witcher"},
    "downloads": {"installers": [
        {"os": "mac", "version": "1.0"},
        {"os": "windows", "version": "1.5"},
        {"os": "windows", "version": "0.9"},
    ]},
}

API_URL = "https://api.gog.com/products/1207658924?expand=downloads"


@pytest.fixture
def product(monkeypatch, reachable, no_manifest):
    state = {"json": json.loads(json.dumps(PRODUCT)), "fetched": []}
    reachable["all"] = True

    def get_remote_json(url, **kwargs):
        state["fetched"].append(url)
        return state["json"]
    monkeypatch.setattr(gog.network, "get_remote_json", get_remote_json)
    return state


def test_product_info_is_read_from_the_api(gog_store, product):
    data = gog_store.get_latest_jsondata("1207658924")

    assert product["fetched"] == [API_URL]
    assert data.get_value(config.json_key_store_appid) == "1207658924"
    assert data.get_value(config.json_key_store_appname) == "the_witcher"
    assert data.get_value(config.json_key_store_name) == "The Witcher"
    assert data.get_value(config.json_key_store_appurl) == "https://www.gog.com/game/the_witcher"


def test_the_build_is_the_first_installer_for_the_preferred_platform(gog_store, product):
    assert gog_store.get_latest_jsondata("1207658924").get_value(config.json_key_store_buildid) == "1.5"

    gog_store.platform = "mac"
    assert gog_store.get_latest_jsondata("1207658924").get_value(config.json_key_store_buildid) == "1.0"


def test_a_versionless_installer_keeps_the_default_build(gog_store, product):
    product["json"]["downloads"]["installers"] = [{"os": "windows", "version": ""}, {"os": "windows"}]
    assert gog_store.get_latest_jsondata("1207658924").get_value(config.json_key_store_buildid) == config.default_buildid

    product["json"]["downloads"]["installers"] = [{"os": "windows"}]
    assert gog_store.get_latest_jsondata("1207658924").get_value(config.json_key_store_buildid) == config.default_buildid


def test_no_installer_for_the_platform_keeps_the_default_build(gog_store, product):
    gog_store.platform = "linux"

    assert gog_store.get_latest_jsondata("1207658924").get_value(config.json_key_store_buildid) == config.default_buildid


def test_an_unreachable_product_card_falls_back_to_the_store_page(gog_store, product, reachable):
    reachable["all"] = False
    reachable["ok"] = {API_URL, "https://www.gog.com/en/game/the_witcher"}

    data = gog_store.get_latest_jsondata("1207658924")

    assert data.get_value(config.json_key_store_appurl) == "https://www.gog.com/en/game/the_witcher"


def test_no_reachable_page_leaves_the_url_unset(gog_store, product, reachable):
    reachable["all"] = False
    reachable["ok"] = {API_URL}

    data = gog_store.get_latest_jsondata("1207658924")

    assert data.get_value(config.json_key_store_appurl) is None


def test_product_info_needs_the_api(gog_store, product, reachable):
    product["json"] = None
    assert gog_store.get_latest_jsondata("1207658924") is None

    reachable["all"] = False
    assert gog_store.get_latest_jsondata("1207658924") is None
    assert len(product["fetched"]) == 1


def test_an_invalid_info_identifier_asks_nothing(gog_store, product):
    assert gog_store.get_latest_jsondata("") is None
    assert product["fetched"] == []


def test_the_version_comes_from_the_product_info(gog_store, product):
    assert gog_store.get_latest_version("1207658924") == "1.5"


def test_manifest_paths_join_the_product_info(gog_store, product, monkeypatch):
    class Entry:
        def get_paths(self, base_path):
            return [base_path + "/saves", "STORE_INSTALL_DIR/skipped"]
        def get_keys(self):
            return ["HKEY_CURRENT_USER/Software/CD Projekt"]

    class OneEntryManifest:
        def find_entry_by_gogid(self, gogid, **kwargs):
            return Entry() if gogid == "1207658924" else None
        def find_entry_by_name(self, **kwargs):
            return None

    monkeypatch.setattr(gog.manifest, "get_manifest_instance", lambda: OneEntryManifest())
    data = gog_store.get_latest_jsondata("1207658924")

    assert data.get_value(config.json_key_store_paths) == [config.token_game_install_dir + "/saves"]
    assert data.get_value(config.json_key_store_keys) == ["HKEY_CURRENT_USER/Software/CD Projekt"]
