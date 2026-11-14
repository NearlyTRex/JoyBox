# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import squareenix
from stores_helpers import build_with_install_dir, every_identifier, platform_placement

SECTION = "UserData.SquareEnix"
FIELD = "squareenix_install_dir"


@pytest.fixture
def squareenix_store(isolated_settings, tmp_path):
    return build_with_install_dir(isolated_settings, squareenix.SquareEnix, SECTION, FIELD, str(tmp_path / "SquareEnix"))


###########################################################
# Construction
###########################################################

def test_an_install_dir_is_required(isolated_settings):
    isolated_settings.set_value(SECTION, FIELD, "")

    with pytest.raises(RuntimeError, match = "valid install dir"):
        squareenix.SquareEnix()


def test_the_default_install_dir_is_under_home(isolated_settings, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))

    assert squareenix.SquareEnix().get_install_dir() == str(tmp_path / "Games" / "SquareEnix")


def test_the_install_dir_expands_variables(isolated_settings, monkeypatch, tmp_path):
    monkeypatch.setenv("JOYBOX_GAMES", str(tmp_path))
    store = build_with_install_dir(isolated_settings, squareenix.SquareEnix, SECTION, FIELD, "$JOYBOX_GAMES/SquareEnix")

    assert store.get_install_dir() == str(tmp_path / "SquareEnix")


###########################################################
# Store
###########################################################

def test_the_store_describes_itself(squareenix_store, tmp_path):
    assert squareenix_store.get_name() == config.StoreType.SQUARE_ENIX.val()
    assert squareenix_store.get_type() == config.StoreType.SQUARE_ENIX
    assert squareenix_store.get_platform() == config.Platform.COMPUTER_SQUARE_ENIX
    assert squareenix_store.get_supercategory() == config.Supercategory.ROMS
    assert squareenix_store.get_category() == config.Category.COMPUTER
    assert squareenix_store.get_subcategory() == config.Subcategory.COMPUTER_SQUARE_ENIX
    assert squareenix_store.get_key() == config.json_key_squareenix
    assert squareenix_store.get_install_dir() == str(tmp_path / "SquareEnix")


def test_the_platform_files_games_where_the_store_does(squareenix_store):
    assert platform_placement(squareenix_store) == (
        squareenix_store.get_supercategory(), squareenix_store.get_category(), squareenix_store.get_subcategory())
    assert squareenix_store.get_key() in config.platforms[squareenix_store.get_platform()][config.platform_key_merge_json]
    assert squareenix_store.get_key() in config.json_keys_store


def test_every_identifier_is_the_store_name(squareenix_store):
    assert squareenix_store.get_identifier_keys() == every_identifier(config.json_key_store_name)
    assert squareenix_store.get_install_identifier_key() == config.json_key_store_name
    assert squareenix_store.get_page_identifier_key() == config.json_key_store_name


def test_it_imports_and_downloads_nothing(squareenix_store):
    assert not squareenix_store.can_import_purchases()
    assert not squareenix_store.can_download_purchases()
