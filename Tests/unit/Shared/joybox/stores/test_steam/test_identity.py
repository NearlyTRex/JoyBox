# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import steam
from steam_helpers import ACCOUNT, STEAMID64
from stores_helpers import STEAM_APPID


###########################################################
# Steam paths
#
# The prefix and manifest paths are how a Steam game's wine prefix and
# install state are found, so a wrong layout silently finds nothing.
###########################################################

INSTALL_DIR = "/home/user/.steam/steam"


def test_a_prefix_sits_under_compatdata():
    assert steam.get_steam_prefix_dir(INSTALL_DIR, STEAM_APPID) == \
        os.path.join(INSTALL_DIR, "steamapps", "compatdata", STEAM_APPID, "pfx")


def test_a_prefix_is_specific_to_the_app():
    assert steam.get_steam_prefix_dir(INSTALL_DIR, "220") != \
        steam.get_steam_prefix_dir(INSTALL_DIR, "440")


def test_a_prefix_sits_under_the_install_directory():
    assert steam.get_steam_prefix_dir(INSTALL_DIR, STEAM_APPID).startswith(INSTALL_DIR)


def test_a_manifest_is_named_for_the_app():
    assert steam.get_steam_manifest_file(INSTALL_DIR, STEAM_APPID) == \
        os.path.join(INSTALL_DIR, "steamapps", f"appmanifest_{STEAM_APPID}.acf")


def test_a_manifest_is_specific_to_the_app():
    assert steam.get_steam_manifest_file(INSTALL_DIR, "220") != \
        steam.get_steam_manifest_file(INSTALL_DIR, "440")


def test_the_manifest_and_prefix_share_the_steamapps_root():
    prefix = steam.get_steam_prefix_dir(INSTALL_DIR, STEAM_APPID)
    manifest = steam.get_steam_manifest_file(INSTALL_DIR, STEAM_APPID)

    assert os.path.join(INSTALL_DIR, "steamapps") in prefix
    assert os.path.join(INSTALL_DIR, "steamapps") in manifest


@pytest.mark.parametrize("appid", ["220", "1091500", "0"])
def test_any_appid_builds_a_path(appid):
    assert appid in steam.get_steam_prefix_dir(INSTALL_DIR, appid)
    assert appid in steam.get_steam_manifest_file(INSTALL_DIR, appid)


def test_an_integer_appid_is_accepted():
    # App ids arrive from json as ints as often as strings.
    assert "220" in steam.get_steam_manifest_file(INSTALL_DIR, 220)


###########################################################
# Steam ids
###########################################################

@pytest.mark.parametrize("id_format", config.SteamIDFormatType.members())
def test_every_id_format_is_named(id_format):
    assert id_format.val()


def test_the_id_formats_are_distinct():
    values = [entry.val() for entry in config.SteamIDFormatType.members()]

    assert len(values) == len(set(values))


###########################################################
# Steam user ids
#
# The same account is addressed four different ways depending on which file
# is being read, and a wrong conversion points at another user's data.
###########################################################

def test_the_default_id_is_the_64_bit_one(steam_store):
    assert steam_store.get_user_id() == STEAMID64


def test_the_long_account_id_is_bracketed(steam_store):
    assert steam_store.get_user_id(config.SteamIDFormatType.STEAMID_3L) == \
        "[U:1:%d]" % ACCOUNT


def test_the_short_account_id_is_the_bare_number(steam_store):
    assert steam_store.get_user_id(config.SteamIDFormatType.STEAMID_3S) == str(ACCOUNT)


def test_the_classic_id_carries_its_parity(steam_store):
    # STEAM_0:Y:Z splits the account id into a parity bit and a half, and
    # getting the parity wrong names a different account.
    classic = steam_store.get_user_id(config.SteamIDFormatType.STEAMID_CL)

    assert classic.startswith("STEAM_0:")
    assert classic == "STEAM_0:%d:%d" % (ACCOUNT % 2, ACCOUNT // 2)


def test_an_odd_account_carries_the_odd_parity(steam_store, isolated_settings):
    isolated_settings.set_value("UserData.Steam", "steam_userid", str(int(STEAMID64) + 1))

    assert steam.Steam().get_user_id(config.SteamIDFormatType.STEAMID_CL) == "STEAM_0:1:%d" % (ACCOUNT // 2)


def test_the_short_classic_id_is_the_halved_account(steam_store):
    assert steam_store.get_user_id(config.SteamIDFormatType.STEAMID_CS) == str(ACCOUNT // 2)


def test_every_id_format_produces_something_different(steam_store):
    produced = [
        steam_store.get_user_id(format_type)
        for format_type in config.SteamIDFormatType.members()
    ]

    assert len(set(produced)) == len(produced)


###########################################################
# Store identity
###########################################################

def test_the_store_knows_its_own_name(steam_store):
    assert steam_store.get_name() == config.StoreType.STEAM.val()


def test_the_store_reports_its_configured_account(steam_store):
    assert steam_store.get_account_name() == "player"
    assert steam_store.get_user_name() == "Player"


def test_the_store_reports_its_install_directory(steam_store, tmp_path):
    assert steam_store.get_install_dir() == str(tmp_path / "steam")


def test_the_store_can_install_and_launch(steam_store):
    # Steam is one of the few stores that owns the whole lifecycle.
    assert steam_store.can_handle_installing() is True
    assert steam_store.can_handle_launching() is True


def test_the_store_can_import_and_download_purchases(steam_store):
    assert steam_store.can_import_purchases() is True
    assert steam_store.can_download_purchases() is True


@pytest.mark.parametrize("key,value", [
    ("steam_platform", ""),
    ("steam_accountname", ""),
    ("steam_username", ""),
    ("steam_web_api_key", ""),
])
def test_a_store_without_its_settings_refuses_to_start(isolated_settings, tmp_path, key, value):
    # Half-configured, the store would build paths against empty values.
    install_dir = tmp_path / "steam"
    install_dir.mkdir()
    for setting_key, setting_value in [
        ("steam_platform", "linux"),
        ("steam_arch", "64"),
        ("steam_accountname", "player"),
        ("steam_username", "Player"),
        ("steam_userid", STEAMID64),
        ("steam_web_api_key", "apikey"),
        ("steam_install_dir", str(install_dir)),
    ]:
        isolated_settings.set_value("UserData.Steam", setting_key, setting_value)
    isolated_settings.set_value("UserData.Steam", key, value)

    with pytest.raises(RuntimeError):
        steam.Steam()
