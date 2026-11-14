# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import redcandle
from stores_helpers import build_with_install_dir, every_identifier, platform_placement

SECTION = "UserData.RedCandle"
FIELD = "redcandle_install_dir"


@pytest.fixture
def redcandle_store(isolated_settings, tmp_path):
    return build_with_install_dir(isolated_settings, redcandle.RedCandle, SECTION, FIELD, str(tmp_path / "RedCandle"))


###########################################################
# Construction
###########################################################

def test_an_install_dir_is_required(isolated_settings):
    isolated_settings.set_value(SECTION, FIELD, "")

    with pytest.raises(RuntimeError, match = "valid install dir"):
        redcandle.RedCandle()


def test_the_default_install_dir_is_under_home(isolated_settings, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))

    assert redcandle.RedCandle().get_install_dir() == str(tmp_path / "Games" / "RedCandle")


def test_the_install_dir_expands_variables(isolated_settings, monkeypatch, tmp_path):
    monkeypatch.setenv("JOYBOX_GAMES", str(tmp_path))
    store = build_with_install_dir(isolated_settings, redcandle.RedCandle, SECTION, FIELD, "$JOYBOX_GAMES/RedCandle")

    assert store.get_install_dir() == str(tmp_path / "RedCandle")


###########################################################
# Store
###########################################################

def test_the_store_describes_itself(redcandle_store, tmp_path):
    assert redcandle_store.get_name() == config.StoreType.RED_CANDLE.val()
    assert redcandle_store.get_type() == config.StoreType.RED_CANDLE
    assert redcandle_store.get_platform() == config.Platform.COMPUTER_RED_CANDLE
    assert redcandle_store.get_supercategory() == config.Supercategory.ROMS
    assert redcandle_store.get_category() == config.Category.COMPUTER
    assert redcandle_store.get_subcategory() == config.Subcategory.COMPUTER_RED_CANDLE
    assert redcandle_store.get_key() == config.json_key_redcandle
    assert redcandle_store.get_install_dir() == str(tmp_path / "RedCandle")


def test_the_platform_files_games_where_the_store_does(redcandle_store):
    assert platform_placement(redcandle_store) == (
        redcandle_store.get_supercategory(), redcandle_store.get_category(), redcandle_store.get_subcategory())
    assert redcandle_store.get_key() in config.platforms[redcandle_store.get_platform()][config.platform_key_merge_json]
    assert redcandle_store.get_key() in config.json_keys_store


def test_every_identifier_is_the_store_name(redcandle_store):
    assert redcandle_store.get_identifier_keys() == every_identifier(config.json_key_store_name)
    assert redcandle_store.get_install_identifier_key() == config.json_key_store_name
    assert redcandle_store.get_page_identifier_key() == config.json_key_store_name


def test_it_imports_and_downloads_nothing(redcandle_store):
    assert not redcandle_store.can_import_purchases()
    assert not redcandle_store.can_download_purchases()
