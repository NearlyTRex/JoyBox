# Local imports
from joybox import config

###########################################################
# Purchases
#
# The field of each purchase a store returned, in order.
###########################################################

def appids(purchases):
    return [purchase.get_value(config.JSON_KEY_STORE_APPID) for purchase in purchases]


def names(purchases):
    return [purchase.get_value(config.JSON_KEY_STORE_NAME) for purchase in purchases]


###########################################################
# Install dir stores
#
# Stores configured by nothing but an install dir.
###########################################################

def build_with_install_dir(isolated_settings, store_class, section, field, install_dir):
    isolated_settings.set_value(section, field, install_dir)
    return store_class()


def platform_placement(store):
    entry = config.platforms[store.get_platform()]
    return (entry[config.PLATFORM_KEY_SUPERCATEGORY],
            entry[config.PLATFORM_KEY_CATEGORY],
            entry[config.PLATFORM_KEY_SUBCATEGORY])


def every_identifier(json_key):
    return {identifier_type: json_key for identifier_type in config.StoreIdentifierType}


###########################################################
# Steam
###########################################################

# Half-Life 2
STEAM_APPID = "220"
