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

# Prepare store
def PrepareStore(
    instance,
    login = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if instance and login:
        instance.Login(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return instance

# Get store by name
def GetStoreByName(
    store_name,
    login = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for instance in GetStoreList():
        if instance.GetName() == store_name:
            return PrepareStore(instance, login, verbose, pretend_run, exit_on_failure)
    return None

# Get store by type
def GetStoreByType(
    store_type,
    login = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for instance in GetStoreList():
        if instance.GetType() == store_type:
            return PrepareStore(instance, login, verbose, pretend_run, exit_on_failure)
    return None

# Get store by platform
def GetStoreByPlatform(
    store_platform,
    login = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for instance in GetStoreList():
        if instance.GetPlatform() == store_platform:
            return PrepareStore(instance, login, verbose, pretend_run, exit_on_failure)
    return None

# Get store by categories
def GetStoreByCategories(
    store_supercategory,
    store_category,
    store_subcategory,
    login = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for instance in GetStoreList():
        same_supercategory = instance.GetSupercategory() == store_supercategory
        same_category = instance.GetCategory() == store_category
        same_subcategory = instance.GetSubcategory() == store_subcategory
        if same_supercategory and same_category and same_subcategory:
            return PrepareStore(instance, login, verbose, pretend_run, exit_on_failure)
    return None

# Check if store platform
def IsStorePlatform(store_platform):
    return GetStoreByPlatform(store_platform) is not None

# Check if store can handle installing
def can_handle_installing(store_platform):
    instance = GetStoreByPlatform(store_platform)
    if instance:
        return instance.CanHandleInstalling()
    return False

# Check if store can handle launching
def can_handle_launching(store_platform):
    instance = GetStoreByPlatform(store_platform)
    if instance:
        return instance.CanHandleLaunching()
    return False

# Check if purchases can be imported
def can_import_purchases(store_platform):
    instance = GetStoreByPlatform(store_platform)
    if instance:
        return instance.CanImportPurchases()
    return False

# Check if purchases can be downloaded
def can_download_purchases(store_platform):
    instance = GetStoreByPlatform(store_platform)
    if instance:
        return instance.CanDownloadPurchases()
    return False
