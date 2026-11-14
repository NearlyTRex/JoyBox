# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import puppetcombo
from stores_helpers import build_with_install_dir, every_identifier, platform_placement

SECTION = "UserData.PuppetCombo"
FIELD = "puppetcombo_install_dir"


@pytest.fixture
def puppetcombo_store(isolated_settings, tmp_path):
    return build_with_install_dir(isolated_settings, puppetcombo.PuppetCombo, SECTION, FIELD, str(tmp_path / "PuppetCombo"))


###########################################################
# Construction
###########################################################

def test_an_install_dir_is_required(isolated_settings):
    isolated_settings.set_value(SECTION, FIELD, "")

    with pytest.raises(RuntimeError, match = "valid install dir"):
        puppetcombo.PuppetCombo()


def test_the_default_install_dir_is_under_home(isolated_settings, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))

    assert puppetcombo.PuppetCombo().get_install_dir() == str(tmp_path / "Games" / "PuppetCombo")


def test_the_install_dir_expands_variables(isolated_settings, monkeypatch, tmp_path):
    monkeypatch.setenv("JOYBOX_GAMES", str(tmp_path))
    store = build_with_install_dir(isolated_settings, puppetcombo.PuppetCombo, SECTION, FIELD, "$JOYBOX_GAMES/PuppetCombo")

    assert store.get_install_dir() == str(tmp_path / "PuppetCombo")


###########################################################
# Store
###########################################################

def test_the_store_describes_itself(puppetcombo_store, tmp_path):
    assert puppetcombo_store.get_name() == config.StoreType.PUPPET_COMBO.val()
    assert puppetcombo_store.get_type() == config.StoreType.PUPPET_COMBO
    assert puppetcombo_store.get_platform() == config.Platform.COMPUTER_PUPPET_COMBO
    assert puppetcombo_store.get_supercategory() == config.Supercategory.ROMS
    assert puppetcombo_store.get_category() == config.Category.COMPUTER
    assert puppetcombo_store.get_subcategory() == config.Subcategory.COMPUTER_PUPPET_COMBO
    assert puppetcombo_store.get_key() == config.json_key_puppetcombo
    assert puppetcombo_store.get_install_dir() == str(tmp_path / "PuppetCombo")


def test_the_platform_files_games_where_the_store_does(puppetcombo_store):
    assert platform_placement(puppetcombo_store) == (
        puppetcombo_store.get_supercategory(), puppetcombo_store.get_category(), puppetcombo_store.get_subcategory())
    assert puppetcombo_store.get_key() in config.platforms[puppetcombo_store.get_platform()][config.platform_key_merge_json]
    assert puppetcombo_store.get_key() in config.json_keys_store


def test_every_identifier_is_the_store_name(puppetcombo_store):
    assert puppetcombo_store.get_identifier_keys() == every_identifier(config.json_key_store_name)
    assert puppetcombo_store.get_install_identifier_key() == config.json_key_store_name
    assert puppetcombo_store.get_page_identifier_key() == config.json_key_store_name


def test_it_imports_and_downloads_nothing(puppetcombo_store):
    assert not puppetcombo_store.can_import_purchases()
    assert not puppetcombo_store.can_download_purchases()
