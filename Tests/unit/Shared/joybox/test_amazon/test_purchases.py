# Imports
import json
import os
import time

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import amazon
from amazon_helpers import NILE, PYTHON

GREEN = "\x1b[32m"
RED = "\x1b[31m"
CLEAR = "\x1b[0m"

LIBRARY = (
    "Deponia ID: amzn1.adg.product.aaa GENRES: ['Adventure']\n"
    "(INSTALLED) Tomb Raider ID: amzn1.adg.product.bbb GENRES: ['Action', 'Adventure']\n"
    "\n*** TOTAL 2 ***\n")


@pytest.fixture
def library(amazon_store, tools, recording_command, monkeypatch, tmp_path):
    recording_command.output = LIBRARY
    monkeypatch.setattr(amazon_store, "get_purchases_cache_dir", lambda: str(tmp_path / "cache"))
    return {"cache": tmp_path / "cache" / "amazon_purchases_cache.json"}


def appids(purchases):
    return [purchase.get_value(config.json_key_store_appid) for purchase in purchases]


def names(purchases):
    return [purchase.get_value(config.json_key_store_name) for purchase in purchases]


###########################################################
# Fetching
###########################################################

def test_the_library_becomes_purchases(amazon_store, library, recording_command):
    purchases = amazon_store.get_latest_purchases()

    assert appids(purchases) == ["amzn1.adg.product.aaa", "amzn1.adg.product.bbb"]
    assert names(purchases) == ["Deponia", "Tomb Raider"]
    assert all(purchase.get_platform() == config.Platform.COMPUTER_AMAZON_GAMES for purchase in purchases)


def test_nile_refreshes_and_syncs_before_listing(amazon_store, library, recording_command):
    amazon_store.get_latest_purchases()

    assert [call["cmd"] for call in recording_command.calls] == [
        [PYTHON, NILE, "--quiet", "auth", "--refresh"],
        [PYTHON, NILE, "--quiet", "library", "sync"],
        [PYTHON, NILE, "library", "list"]]


def test_colored_output_is_parsed_like_plain_output(amazon_store, library, recording_command):
    recording_command.output = (
        "%s(INSTALLED) %sTomb Raider %sID: amzn1.adg.product.bbb%s GENRES: ['Action']\n"
        "%s%sDeponia %sID: amzn1.adg.product.aaa%s \n" % (GREEN, CLEAR, RED, CLEAR, GREEN, CLEAR, RED, CLEAR))

    purchases = amazon_store.get_latest_purchases()

    assert names(purchases) == ["Tomb Raider", "Deponia"]
    assert appids(purchases) == ["amzn1.adg.product.bbb", "amzn1.adg.product.aaa"]


def test_a_game_without_genres_is_still_a_purchase(amazon_store, library, recording_command):
    recording_command.output = "Deponia ID: amzn1.adg.product.aaa \n\n*** TOTAL 1 ***\n"

    assert appids(amazon_store.get_latest_purchases()) == ["amzn1.adg.product.aaa"]


def test_titles_keep_markers_and_id_text_that_belong_to_them(amazon_store, library, recording_command):
    recording_command.output = (
        "Spy ID: Origins ID: amzn1.adg.product.ccc GENRES: ['Action']\n"
        "(INSTALLED) Why (INSTALLED) Matters ID: amzn1.adg.product.ddd\n")

    purchases = amazon_store.get_latest_purchases()

    assert names(purchases) == ["Spy ID: Origins", "Why (INSTALLED) Matters"]
    assert appids(purchases) == ["amzn1.adg.product.ccc", "amzn1.adg.product.ddd"]


def test_an_empty_library_is_no_purchases(amazon_store, library, recording_command):
    recording_command.output = "\n*** TOTAL 0 ***\n"

    assert amazon_store.get_latest_purchases() == []


def test_no_listing_is_a_failure(amazon_store, library, recording_command):
    recording_command.output = ""

    assert amazon_store.get_latest_purchases() is None
    assert not library["cache"].exists()


@pytest.mark.parametrize("failing", [0, 1])
def test_a_failed_refresh_or_sync_stops_the_listing(amazon_store, library, monkeypatch, failing):
    ran = []

    def run_returncode_command(cmd, **kwargs):
        ran.append(cmd)
        return 1 if len(ran) - 1 == failing else 0
    monkeypatch.setattr(amazon.command, "run_returncode_command", run_returncode_command)

    assert amazon_store.get_latest_purchases() is None
    assert len(ran) == failing + 1
    assert not library["cache"].exists()


@pytest.mark.parametrize("tool", ["PythonVenvPython", "Nile"])
def test_purchases_need_python_and_nile(amazon_store, library, tools, recording_command, tool):
    del tools[tool]

    assert amazon_store.get_latest_purchases() is None
    assert recording_command.calls == []


###########################################################
# Caching
###########################################################

def test_purchases_are_cached_for_a_day(amazon_store, library, recording_command):
    amazon_store.get_latest_purchases(verbose = True)
    recording_command.output = ""

    again = amazon_store.get_latest_purchases(verbose = True)

    assert len(recording_command.calls) == 3
    assert names(again) == ["Deponia", "Tomb Raider"]
    assert appids(again) == ["amzn1.adg.product.aaa", "amzn1.adg.product.bbb"]
    assert again[0].get_platform() == config.Platform.COMPUTER_AMAZON_GAMES


def test_the_cache_holds_names_and_appids(amazon_store, library):
    amazon_store.get_latest_purchases()

    assert json.loads(library["cache"].read_text()) == [
        {config.json_key_store_appid: "amzn1.adg.product.aaa", config.json_key_store_name: "Deponia"},
        {config.json_key_store_appid: "amzn1.adg.product.bbb", config.json_key_store_name: "Tomb Raider"}]


def test_an_empty_library_is_cached_too(amazon_store, library, recording_command):
    recording_command.output = "\n*** TOTAL 0 ***\n"
    amazon_store.get_latest_purchases()

    assert amazon_store.get_latest_purchases() == []
    assert len(recording_command.calls) == 3


def test_a_stale_cache_is_refreshed(amazon_store, library, recording_command):
    amazon_store.get_latest_purchases()
    day_ago = time.time() - 25 * 3600
    os.utime(library["cache"], (day_ago, day_ago))

    amazon_store.get_latest_purchases()

    assert len(recording_command.calls) == 6


@pytest.mark.parametrize("verbose", [False, True])
@pytest.mark.parametrize("content", [{"not": "a list"}, ["not an entry"], "{broken"])
def test_an_unreadable_cache_is_refetched(amazon_store, library, recording_command, content, verbose):
    library["cache"].parent.mkdir(parents = True)
    library["cache"].write_text(content if isinstance(content, str) else json.dumps(content))

    assert len(amazon_store.get_latest_purchases(verbose = verbose)) == 2
    assert len(recording_command.calls) == 3


@pytest.mark.parametrize("verbose", [False, True])
def test_a_failed_cache_write_still_returns_purchases(amazon_store, library, monkeypatch, verbose):
    monkeypatch.setattr(amazon.serialization, "write_json_file", lambda **kwargs: False)

    assert len(amazon_store.get_latest_purchases(verbose = verbose)) == 2
