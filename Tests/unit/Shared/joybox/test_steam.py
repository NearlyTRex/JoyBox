# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import steam


###########################################################
# Steam paths
#
# The prefix and manifest paths are how a Steam game's wine prefix and
# install state are found, so a wrong layout silently finds nothing.
###########################################################

INSTALL_DIR = "/home/user/.steam/steam"
APPID = "220"


def test_a_prefix_sits_under_compatdata():
    assert steam.get_steam_prefix_dir(INSTALL_DIR, APPID) == \
        os.path.join(INSTALL_DIR, "steamapps", "compatdata", APPID, "pfx")


def test_a_prefix_is_specific_to_the_app():
    assert steam.get_steam_prefix_dir(INSTALL_DIR, "220") != \
        steam.get_steam_prefix_dir(INSTALL_DIR, "440")


def test_a_prefix_sits_under_the_install_directory():
    assert steam.get_steam_prefix_dir(INSTALL_DIR, APPID).startswith(INSTALL_DIR)


def test_a_manifest_is_named_for_the_app():
    assert steam.get_steam_manifest_file(INSTALL_DIR, APPID) == \
        os.path.join(INSTALL_DIR, "steamapps", f"appmanifest_{APPID}.acf")


def test_a_manifest_is_specific_to_the_app():
    assert steam.get_steam_manifest_file(INSTALL_DIR, "220") != \
        steam.get_steam_manifest_file(INSTALL_DIR, "440")


def test_the_manifest_and_prefix_share_the_steamapps_root():
    prefix = steam.get_steam_prefix_dir(INSTALL_DIR, APPID)
    manifest = steam.get_steam_manifest_file(INSTALL_DIR, APPID)

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
