# Imports
from . import steam

# Stores instances
instances = [
    steam.Steam()
]

# Get stores
def GetStores():
    return instances
