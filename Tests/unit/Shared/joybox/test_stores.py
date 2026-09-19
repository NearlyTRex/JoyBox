# Imports
import pytest

# Local imports
from joybox import config


###########################################################
# Store registry
#
# Stores read credentials at construction, so the whole registry is unbuildable
# without them. These fill in placeholders to exercise the registry shape
# rather than any real account.
###########################################################

STORE_CREDENTIALS = [
    ("UserData.Epic", "epic_username", "testuser"),
    ("UserData.GOG", "gog_username", "testuser"),
    ("UserData.GOG", "gog_email", "test@example.com"),
    ("UserData.GOG", "gog_platform", "windows"),
    ("UserData.HumbleBundle", "humblebundle_username", "testuser"),
    ("UserData.HumbleBundle", "humblebundle_email", "test@example.com"),
    ("UserData.HumbleBundle", "humblebundle_auth_token", "token"),
    ("UserData.HumbleBundle", "humblebundle_platform", "windows"),
    ("UserData.Legacy", "legacy_username", "testuser"),
    ("UserData.Steam", "steam_username", "testuser"),
    ("UserData.Steam", "steam_accountname", "testaccount"),
    ("UserData.Steam", "steam_userid", "1"),
    ("UserData.Steam", "steam_web_api_key", "key"),
]


@pytest.fixture
def store_list(isolated_settings):
    for section, key, value in STORE_CREDENTIALS:
        isolated_settings.set_value(section, key, value)

    import joybox.stores as stores
    return list(stores.get_store_list())


def test_the_registry_is_populated(store_list):
    assert len(store_list) > 5


def test_every_store_has_a_name(store_list):
    for store in store_list:
        assert store.get_name() and store.get_name().strip()


def test_store_names_are_unique(store_list):
    names = [store.get_name() for store in store_list]
    duplicates = sorted({name for name in names if names.count(name) > 1})

    assert not duplicates, f"duplicate store names: {duplicates}"


def test_store_keys_are_unique(store_list):
    # The key names the section inside a game's json, so a collision would put
    # two stores' data in one place.
    keys = [store.get_key() for store in store_list]
    duplicates = sorted({key for key in keys if keys.count(key) > 1})

    assert not duplicates, f"duplicate store keys: {duplicates}"


def test_store_types_are_unique(store_list):
    types = [str(store.get_type()) for store in store_list]
    duplicates = sorted({entry for entry in types if types.count(entry) > 1})

    assert not duplicates, f"duplicate store types: {duplicates}"


def test_every_store_key_is_a_known_json_key(store_list):
    # get_store_by_platform resolves through these, so an unknown key would
    # write a section nothing else reads.
    for store in store_list:
        assert store.get_key() in config.json_keys_store, \
            f"{store.get_name()} uses unregistered key {store.get_key()!r}"


def test_a_store_is_found_by_its_name(store_list):
    import joybox.stores as stores

    for store in store_list:
        found = stores.get_store_by_name(store.get_name())
        assert found is not None, f"{store.get_name()} is not findable by name"


def test_a_store_is_found_by_its_type(store_list):
    import joybox.stores as stores

    for store in store_list:
        found = stores.get_store_by_type(store.get_type())
        assert found is not None, f"{store.get_name()} is not findable by type"


def test_an_unknown_store_is_not_found(store_list):
    import joybox.stores as stores

    assert stores.get_store_by_name("not-a-real-store") is None
    assert stores.get_store_by_type("not-a-real-type") is None


def test_every_store_declares_an_identifier_key(store_list):
    # Purchases are matched on this, so a store without one can never match.
    for store in store_list:
        assert store.get_info_identifier_key() is not None, \
            f"{store.get_name()} declares no info identifier"
