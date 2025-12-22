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
from .steam import get_steam_page
from .steam import get_steam_cover
from .steam import get_steam_trailer
from .steam import find_steam_appid_matches
from .steam import find_steam_appid_match
from .steam import find_steam_assets
from .steam import find_steam_griddb_covers
from .zoom import Zoom

# Get store map
def get_store_map():
    instances = {}
    def add_instance(class_name):
        instance = class_name()
        instances[instance.get_name()] = instance
    add_instance(Amazon)
    add_instance(Disc)
    add_instance(Epic)
    add_instance(GOG)
    add_instance(HumbleBundle)
    add_instance(Itchio)
    add_instance(Legacy)
    add_instance(PuppetCombo)
    add_instance(RedCandle)
    add_instance(SquareEnix)
    add_instance(Steam)
    add_instance(Zoom)
    return instances

# Get store list
def get_store_list():
    return get_store_map().values()

# Prepare store
def prepare_store(
    instance,
    login = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if instance and login:
        instance.login(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return instance

# Get store by name
def get_store_by_name(
    store_name,
    login = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for instance in get_store_list():
        if instance.get_name() == store_name:
            return prepare_store(instance, login, verbose, pretend_run, exit_on_failure)
    return None

# Get store by type
def get_store_by_type(
    store_type,
    login = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for instance in get_store_list():
        if instance.get_type() == store_type:
            return prepare_store(instance, login, verbose, pretend_run, exit_on_failure)
    return None

# Get store by platform
def get_store_by_platform(
    store_platform,
    login = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for instance in get_store_list():
        if instance.get_platform() == store_platform:
            return prepare_store(instance, login, verbose, pretend_run, exit_on_failure)
    return None

# Get store by categories
def get_store_by_categories(
    store_supercategory,
    store_category,
    store_subcategory,
    login = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for instance in get_store_list():
        same_supercategory = instance.get_supercategory() == store_supercategory
        same_category = instance.get_category() == store_category
        same_subcategory = instance.get_subcategory() == store_subcategory
        if same_supercategory and same_category and same_subcategory:
            return prepare_store(instance, login, verbose, pretend_run, exit_on_failure)
    return None

# Check if store platform
def is_store_platform(store_platform):
    return get_store_by_platform(store_platform) is not None

# Check if store can handle installing
def can_handle_installing(store_platform):
    instance = get_store_by_platform(store_platform)
    if instance:
        return instance.can_handle_installing()
    return False

# Check if store can handle launching
def can_handle_launching(store_platform):
    instance = get_store_by_platform(store_platform)
    if instance:
        return instance.can_handle_launching()
    return False

# Check if purchases can be imported
def can_import_purchases(store_platform):
    instance = get_store_by_platform(store_platform)
    if instance:
        return instance.can_import_purchases()
    return False

# Check if purchases can be downloaded
def can_download_purchases(store_platform):
    instance = get_store_by_platform(store_platform)
    if instance:
        return instance.can_download_purchases()
    return False
