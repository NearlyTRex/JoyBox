# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import zoom
from stores_helpers import build_with_install_dir, every_identifier, platform_placement

SECTION = "UserData.Zoom"
FIELD = "zoom_install_dir"


@pytest.fixture
def zoom_store(isolated_settings, tmp_path):
    return build_with_install_dir(isolated_settings, zoom.Zoom, SECTION, FIELD, str(tmp_path / "Zoom"))


###########################################################
# Construction
###########################################################

def test_an_install_dir_is_required(isolated_settings):
    isolated_settings.set_value(SECTION, FIELD, "")

    with pytest.raises(RuntimeError, match = "valid install dir"):
        zoom.Zoom()


def test_the_default_install_dir_is_under_home(isolated_settings, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))

    assert zoom.Zoom().get_install_dir() == str(tmp_path / "Games" / "Zoom")


def test_the_install_dir_expands_variables(isolated_settings, monkeypatch, tmp_path):
    monkeypatch.setenv("JOYBOX_GAMES", str(tmp_path))
    store = build_with_install_dir(isolated_settings, zoom.Zoom, SECTION, FIELD, "$JOYBOX_GAMES/Zoom")

    assert store.get_install_dir() == str(tmp_path / "Zoom")


###########################################################
# Store
###########################################################

def test_the_store_describes_itself(zoom_store, tmp_path):
    assert zoom_store.get_name() == config.StoreType.ZOOM.val()
    assert zoom_store.get_type() == config.StoreType.ZOOM
    assert zoom_store.get_platform() == config.Platform.COMPUTER_ZOOM
    assert zoom_store.get_supercategory() == config.Supercategory.ROMS
    assert zoom_store.get_category() == config.Category.COMPUTER
    assert zoom_store.get_subcategory() == config.Subcategory.COMPUTER_ZOOM
    assert zoom_store.get_key() == config.json_key_zoom
    assert zoom_store.get_install_dir() == str(tmp_path / "Zoom")


def test_the_platform_files_games_where_the_store_does(zoom_store):
    assert platform_placement(zoom_store) == (
        zoom_store.get_supercategory(), zoom_store.get_category(), zoom_store.get_subcategory())
    assert zoom_store.get_key() in config.platforms[zoom_store.get_platform()][config.platform_key_merge_json]
    assert zoom_store.get_key() in config.json_keys_store


def test_every_identifier_is_the_store_name(zoom_store):
    assert zoom_store.get_identifier_keys() == every_identifier(config.json_key_store_name)
    assert zoom_store.get_install_identifier_key() == config.json_key_store_name
    assert zoom_store.get_page_identifier_key() == config.json_key_store_name


def test_it_imports_and_downloads_nothing(zoom_store):
    assert not zoom_store.can_import_purchases()
    assert not zoom_store.can_download_purchases()
