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
