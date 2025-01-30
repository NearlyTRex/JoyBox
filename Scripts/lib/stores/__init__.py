# Imports
from .amazon import Amazon
from .disc import Disc
from .epic import Epic
from .gog import GOG
from .humblebundle import HumbleBundle
from .itchio import Itchio
from .legacy import Legacy
from .puppetcombo import PuppetCombo
from .redcandle import RedCandle
from .squareenix import SquareEnix
from .steam import Steam
from .steam import GetSteamPage
from .steam import GetSteamCover
from .steam import GetSteamTrailer
from .steam import FindSteamAppIDMatches
from .steam import FindSteamAppIDMatch
from .steam import FindSteamAssets
from .steam import FindSteamGridDBCovers
from .zoom import Zoom

# Get store map
def GetStoreMap():
    instances = {}
    def AddInstance(class_name):
        instance = class_name()
        instances[instance.GetName()] = instance
    AddInstance(Amazon)
    AddInstance(Disc)
    AddInstance(Epic)
    AddInstance(GOG)
    AddInstance(HumbleBundle)
    AddInstance(Itchio)
    AddInstance(Legacy)
    AddInstance(PuppetCombo)
    AddInstance(RedCandle)
    AddInstance(SquareEnix)
    AddInstance(Steam)
    AddInstance(Zoom)
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
