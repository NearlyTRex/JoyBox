# Imports
import config
from . import amazon
from . import epic
from . import gog
from . import itchio
from . import steam

# Stores instances
instances = [
    amazon.Amazon(),
    epic.Epic(),
    gog.GOG(),
    itchio.Itchio(),
    steam.Steam()
]

# Get stores
def GetStores():
    return instances

# Get store by name
def GetStoreByName(store_name):
    for store_instance in instances:
        if store_instance.GetName() == store_name:
            return store_instance
    return None

# Get store by type
def GetStoreByType(store_type):
    if store_type == config.store_type_amazon:
        return amazon.Amazon()
    elif store_type == config.store_type_epic:
        return epic.Epic()
    elif store_type == config.store_type_gog:
        return gog.GOG()
    elif store_type == config.store_type_itchio:
        return itchio.Itchio()
    elif store_type == config.store_type_steam:
        return steam.Steam()
    return None
