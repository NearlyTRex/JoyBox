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


###########################################################
# The contract every store implements
#
# The collection treats stores interchangeably: it asks any of them for its
# categories, its identifier keys and what it can do, then acts on the answer.
# A store that answers the wrong shape is only found when that store's games
# are handled, which may be long after it was added.
###########################################################

###########################################################
# Identity
###########################################################

def test_every_store_names_a_platform(store_list):
    for store in store_list:
        assert store.get_platform(), "%s has no platform" % store.get_name()


def test_every_store_platform_is_unique(store_list):
    platforms = [store.get_platform() for store in store_list]

    assert len(set(platforms)) == len(platforms)


def test_every_store_is_filed_under_known_categories(store_list):
    for store in store_list:
        assert store.get_supercategory() in config.Supercategory.members()
        assert store.get_category() in config.Category.members()


def test_every_store_subcategory_belongs_to_its_category(store_list):
    # The pair is used to build paths; a subcategory from another category
    # writes the game into a directory nothing reads back.
    for store in store_list:
        allowed = config.subcategory_map[store.get_category()]
        assert store.get_subcategory() in allowed, \
            "%s: %s is not under %s" % (
                store.get_name(), store.get_subcategory(), store.get_category())


def test_every_store_platform_matches_its_categories(store_list):
    from joybox import gameinfo

    for store in store_list:
        derived = gameinfo.derive_game_platform_from_categories(
            store.get_category(), store.get_subcategory())
        assert store.get_platform() == derived, \
            "%s: platform %s does not match %s / %s" % (
                store.get_name(), store.get_platform(),
                store.get_category(), store.get_subcategory())


###########################################################
# Identifier keys
###########################################################

def test_every_store_maps_its_identifier_keys(store_list):
    for store in store_list:
        keys = store.get_identifier_keys()
        assert isinstance(keys, dict), "%s does not map its keys" % store.get_name()
        assert keys, "%s maps no keys" % store.get_name()


def test_every_identifier_type_is_answered(store_list):
    # A store that leaves one out returns None, and the caller looks that up
    # in the json and silently finds nothing.
    for store in store_list:
        for identifier_type in config.StoreIdentifierType.members():
            assert store.get_identifier_key(identifier_type), \
                "%s has no %s identifier" % (store.get_name(), identifier_type)


@pytest.mark.parametrize("getter,identifier_type", [
    ("get_info_identifier_key", config.StoreIdentifierType.INFO),
    ("get_install_identifier_key", config.StoreIdentifierType.INSTALL),
    ("get_launch_identifier_key", config.StoreIdentifierType.LAUNCH),
    ("get_download_identifier_key", config.StoreIdentifierType.DOWNLOAD),
    ("get_asset_identifier_key", config.StoreIdentifierType.ASSET),
    ("get_metadata_identifier_key", config.StoreIdentifierType.METADATA),
    ("get_page_identifier_key", config.StoreIdentifierType.PAGE),
])
def test_each_named_identifier_getter_matches_its_type(store_list, getter, identifier_type):
    # The named getters are thin wrappers, and one wired to the wrong type
    # reads another identifier's key.
    for store in store_list:
        assert getattr(store, getter)() == store.get_identifier_key(identifier_type), \
            "%s: %s does not return its %s key" % (store.get_name(), getter, identifier_type)


def test_every_identifier_key_is_a_known_json_key(store_list):
    for store in store_list:
        for identifier_type, key in store.get_identifier_keys().items():
            assert key in config.json_keys_store_subdata + config.json_keys_store_appdata, \
                "%s: %s is not a stored json key" % (store.get_name(), key)


###########################################################
# Identifier validation
###########################################################

VALIDATORS = [
    "is_valid_identifier",
    "is_valid_info_identifier",
    "is_valid_install_identifier",
    "is_valid_launch_identifier",
    "is_valid_download_identifier",
    "is_valid_asset_identifier",
    "is_valid_metadata_identifier",
    "is_valid_page_identifier",
]


@pytest.mark.parametrize("validator", VALIDATORS)
def test_every_validator_accepts_an_identifier(store_list, validator):
    for store in store_list:
        assert getattr(store, validator)("220") is True, \
            "%s: %s refused an identifier" % (store.get_name(), validator)


@pytest.mark.parametrize("validator", VALIDATORS)
@pytest.mark.parametrize("candidate", ["", None, 220, [], {}])
def test_every_validator_refuses_what_is_not_an_identifier(store_list, validator, candidate):
    # An empty identifier reaches the store as a lookup for everything.
    for store in store_list:
        assert getattr(store, validator)(candidate) is False, \
            "%s: %s accepted %r" % (store.get_name(), validator, candidate)


###########################################################
# Capabilities
###########################################################

CAPABILITIES = [
    "can_handle_installing",
    "can_handle_launching",
    "can_import_purchases",
    "can_download_purchases",
]


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_every_capability_is_answered_with_a_boolean(store_list, capability):
    # These are checked with "is True" in places, so a truthy string or None
    # reads as a refusal.
    for store in store_list:
        answer = getattr(store, capability)()
        assert isinstance(answer, bool), \
            "%s: %s answered %r" % (store.get_name(), capability, answer)


def test_a_store_that_downloads_can_also_import(store_list):
    # Downloading a purchase means knowing it exists, so the pair cannot be
    # the other way round.
    for store in store_list:
        if store.can_download_purchases():
            assert store.can_import_purchases(), \
                "%s downloads purchases it cannot import" % store.get_name()


###########################################################
# Session state
###########################################################

def test_a_store_starts_logged_out(store_list):
    for store in store_list:
        assert store.is_logged_in() is False


def test_a_store_remembers_being_logged_in(store_list):
    for store in store_list:
        store.set_logged_in(True)
        assert store.is_logged_in() is True
        store.set_logged_in(False)
        assert store.is_logged_in() is False


def test_every_store_names_its_own_cookie_file(store_list, monkeypatch):
    # Two stores sharing a cookie file would sign each other out.
    from joybox import webpage

    monkeypatch.setattr(webpage.runtime, "get_cookie_directory", lambda: "/cookies")
    cookie_files = [store.get_cookie_file() for store in store_list]

    assert len(set(cookie_files)) == len(cookie_files)
