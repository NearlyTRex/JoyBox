# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import disc
from stores_helpers import build_with_install_dir, every_identifier, platform_placement

SECTION = "UserData.Disc"
FIELD = "disc_install_dir"


@pytest.fixture
def disc_store(isolated_settings, tmp_path):
    return build_with_install_dir(isolated_settings, disc.Disc, SECTION, FIELD, str(tmp_path / "Disc"))


###########################################################
# Construction
###########################################################

def test_an_install_dir_is_required(isolated_settings):
    isolated_settings.set_value(SECTION, FIELD, "")

    with pytest.raises(RuntimeError, match = "valid install dir"):
        disc.Disc()


def test_the_default_install_dir_is_under_home(isolated_settings, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))

    assert disc.Disc().get_install_dir() == str(tmp_path / "Games" / "Disc")


def test_the_install_dir_expands_variables(isolated_settings, monkeypatch, tmp_path):
    monkeypatch.setenv("JOYBOX_GAMES", str(tmp_path))
    store = build_with_install_dir(isolated_settings, disc.Disc, SECTION, FIELD, "$JOYBOX_GAMES/Disc")

    assert store.get_install_dir() == str(tmp_path / "Disc")


###########################################################
# Store
###########################################################

def test_the_store_describes_itself(disc_store, tmp_path):
    assert disc_store.get_name() == config.StoreType.DISC.val()
    assert disc_store.get_type() == config.StoreType.DISC
    assert disc_store.get_platform() == config.Platform.COMPUTER_DISC
    assert disc_store.get_supercategory() == config.Supercategory.ROMS
    assert disc_store.get_category() == config.Category.COMPUTER
    assert disc_store.get_subcategory() == config.Subcategory.COMPUTER_DISC
    assert disc_store.get_key() == config.json_key_disc
    assert disc_store.get_install_dir() == str(tmp_path / "Disc")


def test_the_platform_files_games_where_the_store_does(disc_store):
    assert platform_placement(disc_store) == (
        disc_store.get_supercategory(), disc_store.get_category(), disc_store.get_subcategory())
    assert disc_store.get_key() in config.platforms[disc_store.get_platform()][config.platform_key_merge_json]
    assert disc_store.get_key() in config.json_keys_store


def test_every_identifier_is_the_store_name(disc_store):
    assert disc_store.get_identifier_keys() == every_identifier(config.json_key_store_name)
    assert disc_store.get_install_identifier_key() == config.json_key_store_name
    assert disc_store.get_page_identifier_key() == config.json_key_store_name


def test_it_imports_and_downloads_nothing(disc_store):
    assert not disc_store.can_import_purchases()
    assert not disc_store.can_download_purchases()
