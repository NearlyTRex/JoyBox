# Local imports
from joybox import config

###########################################################
# Purchases
#
# The field of each purchase a store returned, in order.
###########################################################

def appids(purchases):
    return [purchase.get_value(config.json_key_store_appid) for purchase in purchases]


def names(purchases):
    return [purchase.get_value(config.json_key_store_name) for purchase in purchases]


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
    return (entry[config.platform_key_supercategory],
            entry[config.platform_key_category],
            entry[config.platform_key_subcategory])


def every_identifier(json_key):
    return {identifier_type: json_key for identifier_type in config.StoreIdentifierType}
