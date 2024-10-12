# Imports
from .amazon import Amazon
from .epic import Epic
from .gog import GOG
from .itchio import Itchio
from .steam import Steam

# Get store map
def GetStoreMap():
    instances = {}
    instances["Amazon"] = Amazon()
    instances["Epic"] = Epic()
    instances["GOG"] = GOG()
    instances["Itchio"] = Itchio()
    instances["Steam"] = Steam()
    return instances

# Get store list
def GetStoreList():
    return GetStoreMap().values()

# Get store by name
def GetStoreByName(store_name):
    for instance in GetStoreMap().values():
        if instance.GetName() == store_name:
            return instance
    return None

# Get store by type
def GetStoreByType(store_type):
    for instance in GetStoreMap().values():
        if instance.GetType() == store_type:
            return instance
    return None
