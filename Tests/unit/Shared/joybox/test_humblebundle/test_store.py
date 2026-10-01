# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.stores import humblebundle


###########################################################
# Construction
###########################################################

@pytest.mark.parametrize("field", [
    "humblebundle_username",
    "humblebundle_email",
    "humblebundle_platform",
    "humblebundle_auth_token",
    "humblebundle_install_dir"])
def test_every_account_setting_is_required(humble_settings, field):
    humble_settings.set_value("UserData.HumbleBundle", field, "")

    with pytest.raises(RuntimeError):
        humblebundle.HumbleBundle()


def test_the_install_dir_expands_variables(humble_settings, tmp_path, monkeypatch):
    monkeypatch.setenv("HUMBLE_TEST_ROOT", str(tmp_path))
    humble_settings.set_value("UserData.HumbleBundle", "humblebundle_install_dir", "$HUMBLE_TEST_ROOT/games")

    assert humblebundle.HumbleBundle().get_install_dir() == os.path.join(str(tmp_path), "games")


def test_the_account_comes_from_settings(humble_store, tmp_path):
    assert humble_store.get_user_name() == "player"
    assert humble_store.get_email() == "player@joybox.test"
    assert humble_store.get_preferred_platform() == "windows"
    assert humble_store.get_auth_token() == "token123"
    assert humble_store.get_install_dir() == str(tmp_path / "humble")


def test_the_store_describes_itself(humble_store):
    assert humble_store.get_name() == config.StoreType.HUMBLE_BUNDLE.val()
    assert humble_store.get_type() == config.StoreType.HUMBLE_BUNDLE
    assert humble_store.get_platform() == config.Platform.COMPUTER_HUMBLE_BUNDLE
    assert humble_store.get_supercategory() == config.Supercategory.ROMS
    assert humble_store.get_category() == config.Category.COMPUTER
    assert humble_store.get_subcategory() == config.Subcategory.COMPUTER_HUMBLE_BUNDLE
    assert humble_store.get_key() == config.json_key_humble
    assert humble_store.can_import_purchases() and humble_store.can_download_purchases()


def test_names_find_assets_and_appnames_find_everything_else(humble_store):
    keys = humble_store.get_identifier_keys()

    by_name = [config.StoreIdentifierType.ASSET, config.StoreIdentifierType.METADATA]
    by_appname = [config.StoreIdentifierType.INFO, config.StoreIdentifierType.INSTALL,
                  config.StoreIdentifierType.LAUNCH, config.StoreIdentifierType.DOWNLOAD,
                  config.StoreIdentifierType.PAGE]
    assert all(keys[kind] == config.json_key_store_name for kind in by_name)
    assert all(keys[kind] == config.json_key_store_appname for kind in by_appname)
    assert len(keys) == len(by_name) + len(by_appname)
