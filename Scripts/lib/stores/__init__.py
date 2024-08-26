# Imports
from . import steam

# Stores instances
instances = [
    steam.Steam()
]

# Get stores
def GetStores():
    return instances

# Get store by name
def GetStoreByName(name):
    for store_instance in instances:
        if store_instance.GetName() == name:
            return store_instance
    return None
