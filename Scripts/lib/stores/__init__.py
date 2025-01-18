# Imports
from .amazon import Amazon
from .epic import Epic
from .gog import GOG
from .itchio import Itchio
from .legacy import Legacy
from .steam import Steam
from .steam import GetLikelySteamPage
from .steam import GetLikelySteamCover
from .steam import GetLikelySteamTrailer
from .steam import FindSteamAppIDMatches
from .steam import FindSteamAppIDMatch
from .steam import FindSteamGridDBCovers

# Get store map
def GetStoreMap():
    instances = {}
    def AddInstance(class_name):
        instance = class_name()
        instances[instance.GetName()] = instance
    AddInstance(Amazon)
    AddInstance(Epic)
    AddInstance(GOG)
    AddInstance(Itchio)
    AddInstance(Legacy)
    AddInstance(Steam)
    return instances

# Get store list
def GetStoreList():
    return GetStoreMap().values()

# Get store by name
def GetStoreByName(store_name):
    for instance in GetStoreList():
        if instance.GetName() == store_name:
            return instance
    return None

# Get store by type
def GetStoreByType(store_type):
    for instance in GetStoreList():
        if instance.GetType() == store_type:
            return instance
    return None

# Get store by platform
def GetStoreByPlatform(store_platform):
    for instance in GetStoreList():
        if instance.GetPlatform() == store_platform:
            return instance
    return None
