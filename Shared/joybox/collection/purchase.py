# Imports
import os

# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import prompts
from joybox import serialization
from joybox import environment
from joybox import gamecollection
from joybox import gamenaming
from joybox import storebase
from joybox import stores
from .metadata import create_game_metadata_entry
from .metadata import update_game_metadata_entry
from .jsondata import get_game_json_ignore_entries
from .jsondata import add_game_json_ignore_entry
from .jsondata import create_game_json_file
from .jsondata import update_game_json_file

############################################################

# Sign in to the store for these categories; True when there is no store or it has no login of its own
def login_game_store(
    game_supercategory,
    game_category,
    game_subcategory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    store_obj = stores.get_store_by_categories(
        store_supercategory = game_supercategory,
        store_category = game_category,
        store_subcategory = game_subcategory)
    if not store_obj:
        return True

    # Stores without a login of their own have nothing to log into
    if type(store_obj).login is storebase.StoreBase.login:
        return True
    return store_obj.login(
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Sign in to the store of every ROM category; stops at the first failure
def login_all_game_stores(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory, game_category, game_subcategory in gamecollection.iterate_rom_categories():
        success = login_game_store(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

############################################################

# The store for these categories when it can import purchases; None otherwise
def _get_importable_store(game_supercategory, game_category, game_subcategory):

    # Get store
    store_obj = stores.get_store_by_categories(game_supercategory, game_category, game_subcategory)
    if not store_obj:
        return None

    # Check if purchases can be imported
    if not store_obj.can_import_purchases():
        return None
    return store_obj

# The given purchases, or the store's latest, with the store's ignore entries; None when there are no purchases
def _load_purchases_and_ignores(
    store_obj,
    purchases = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get all purchases
    if purchases is None:
        logger.log_info("Retrieving purchases for %s" % store_obj.get_type())
        purchases = store_obj.get_latest_purchases(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not purchases:
        return None

    # Get all ignores
    logger.log_info("Fetching ignore entries for %s" % store_obj.get_type())
    ignores = get_game_json_ignore_entries(
        game_supercategory = store_obj.get_supercategory(),
        game_category = store_obj.get_category(),
        game_subcategory = store_obj.get_subcategory(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return purchases, ignores

# The importable store for these categories with its purchases and ignore entries; None when there is nothing to do
def _load_store_purchases(
    game_supercategory,
    game_category,
    game_subcategory,
    purchases = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store
    store_obj = _get_importable_store(game_supercategory, game_category, game_subcategory)
    if not store_obj:
        return None

    # Get all purchases and ignores
    loaded = _load_purchases_and_ignores(store_obj, purchases, verbose, pretend_run, exit_on_failure)
    if not loaded:
        return None
    return (store_obj,) + loaded

# The purchase's info identifier and the store's JSON files matching its app id, name or url; None when it has no identifier or is ignored
def _search_purchase_json_files(store_obj, purchase, ignores, exit_on_failure = False):
    purchase_identifiers = [
        purchase.get_value(config.JSON_KEY_STORE_APPID),
        purchase.get_value(config.JSON_KEY_STORE_APPNAME),
        purchase.get_value(config.JSON_KEY_STORE_APPURL)
    ]

    # Get info identifier
    info_identifier = purchase.get_value(store_obj.get_info_identifier_key())
    if not info_identifier:
        return None
    if info_identifier in ignores.keys():
        return None

    # Find matching json files
    json_matches = serialization.search_json_files(
        src = environment.get_json_metadata_dir(
            game_supercategory = store_obj.get_supercategory(),
            game_category = store_obj.get_category(),
            game_subcategory = store_obj.get_subcategory()),
        search_values = purchase_identifiers,
        search_keys = config.json_keys_store_appdata,
        exit_on_failure = exit_on_failure)
    return info_identifier, json_matches

# Log the purchase's app id, name, url and name, then ask whether to import, skip or ignore it
def _prompt_purchase_import(purchase):
    logger.log_info("Found new potential entry:")
    for label, json_key in [
        ("Appid", config.JSON_KEY_STORE_APPID),
        ("Appname", config.JSON_KEY_STORE_APPNAME),
        ("Appurl", config.JSON_KEY_STORE_APPURL),
        ("Name", config.JSON_KEY_STORE_NAME)]:
        value = purchase.get_value(json_key)
        if value:
            logger.log_info(" - %s:\t" % label + value)
    return prompts.prompt_for_value("Import this? (n to skip, i to ignore)", default_value = "y")

# Record the purchase in the store's ignore file; False after logging when that fails
def _ignore_purchase(
    store_obj,
    info_identifier,
    purchase_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    success = add_game_json_ignore_entry(
        game_supercategory = store_obj.get_supercategory(),
        game_category = store_obj.get_category(),
        game_subcategory = store_obj.get_subcategory(),
        game_identifier = info_identifier,
        game_name = purchase_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to add ignore entry for game '%s'" % purchase_name)
        return False
    return True

# Ask for the entry name, defaulting to the game name derived from the purchase name; None after a warning when none is chosen
def _prompt_entry_name(purchase_name):
    default_name = None
    if purchase_name:
        default_name = gamenaming.derive_game_name_from_regular_name(purchase_name)
    entry_name = prompts.prompt_for_value("Choose entry name", default_value = default_name)
    if not entry_name:
        logger.log_warning("No entry name chosen, skipping")
        return None
    return entry_name

# The purchase's app url, looked up from the store by name and saved on the purchase when it had none
def _fill_purchase_appurl(
    store_obj,
    purchase,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    purchase_appurl = purchase.get_value(config.JSON_KEY_STORE_APPURL)
    purchase_name = purchase.get_value(config.JSON_KEY_STORE_NAME)
    if not purchase_appurl and purchase_name:
        purchase_appurl = store_obj.get_latest_url(
            identifier = purchase_name,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if purchase_appurl:
            purchase.set_value(config.JSON_KEY_STORE_APPURL, purchase_appurl)
    return purchase_appurl

# Create the entry's JSON file from the purchase and its metadata entry; False after logging the failed step
def _create_purchase_entries(
    store_obj,
    purchase,
    entry_name,
    purchase_appurl,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create json file
    success = create_game_json_file(
        game_supercategory = store_obj.get_supercategory(),
        game_category = store_obj.get_category(),
        game_subcategory = store_obj.get_subcategory(),
        game_name = entry_name,
        initial_data = {store_obj.get_key(): purchase.get_data_copy()},
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to create json file for game '%s'" % entry_name)
        return False

    # Create metadata entry
    success = create_game_metadata_entry(
        game_supercategory = store_obj.get_supercategory(),
        game_category = store_obj.get_category(),
        game_subcategory = store_obj.get_subcategory(),
        game_name = entry_name,
        game_url = purchase_appurl,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to add metadata entry for game '%s'" % entry_name)
        return False
    return True

# Offer one purchase with no JSON file or ignore entry for import, skipping or ignoring; False only when a write fails
def _import_purchase(
    store_obj,
    purchase,
    ignores,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Skip if ignored or json file already exists
    found = _search_purchase_json_files(store_obj, purchase, ignores, exit_on_failure = exit_on_failure)
    if not found:
        return True
    info_identifier, json_matches = found
    if json_matches:
        return True

    # Determine if this should be imported
    purchase_name = purchase.get_value(config.JSON_KEY_STORE_NAME)
    should_import = _prompt_purchase_import(purchase)
    if should_import.lower() == "n":
        return True

    # Add to ignore
    if should_import.lower() == "i":
        return _ignore_purchase(store_obj, info_identifier, purchase_name, verbose, pretend_run, exit_on_failure)

    # Prompt for entry name
    entry_name = _prompt_entry_name(purchase_name)
    if not entry_name:
        return True

    # Create json file and metadata entry
    purchase_appurl = _fill_purchase_appurl(store_obj, purchase, verbose, pretend_run, exit_on_failure)
    return _create_purchase_entries(store_obj, purchase, entry_name, purchase_appurl, verbose, pretend_run, exit_on_failure)

# Prompt for each store purchase with no JSON file or ignore entry: import it as a JSON file and metadata entry, skip it, or ignore it
def import_game_store_purchases(
    game_supercategory,
    game_category,
    game_subcategory,
    purchases = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store, purchases and ignores
    loaded = _load_store_purchases(game_supercategory, game_category, game_subcategory, purchases, verbose, pretend_run, exit_on_failure)
    if not loaded:
        return True
    store_obj, purchases, ignores = loaded

    # Import each purchase
    logger.log_info("Starting to import purchases for %s" % store_obj.get_type())
    for purchase in purchases:
        success = _import_purchase(
            store_obj = store_obj,
            purchase = purchase,
            ignores = ignores,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Should be successful
    return True

############################################################

# Update the named game's JSON file and metadata entry; False after logging the failed step
def _update_purchase_entries(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    keys = None,
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Update json file
    success = update_game_json_file(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        game_root = None,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to update json file for game '%s'" % game_name)
        return False

    # Update metadata entry
    success = update_game_metadata_entry(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        keys = keys,
        force = force,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to update metadata entry for game '%s'" % game_name)
        return False
    return True

# Refresh one purchase's JSON file and metadata entry when it has a JSON file and is not ignored; False only when an update fails
def _update_purchase(
    store_obj,
    purchase,
    ignores,
    game_supercategory,
    game_category,
    game_subcategory,
    keys = None,
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Find matching json file
    found = _search_purchase_json_files(store_obj, purchase, ignores, exit_on_failure = exit_on_failure)
    if not found:
        return True
    _, json_matches = found
    json_file = None
    if json_matches:
        json_file = json_matches[0]
    if not paths.is_path_file(json_file):
        return True

    # Update json file and metadata entry
    return _update_purchase_entries(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = paths.get_filename_basename(json_file),
        keys = keys,
        force = force,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Refresh the JSON file and metadata entry of each store purchase that already has a JSON file
def update_game_store_purchases(
    game_supercategory,
    game_category,
    game_subcategory,
    purchases = None,
    keys = None,
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store, purchases and ignores
    loaded = _load_store_purchases(game_supercategory, game_category, game_subcategory, purchases, verbose, pretend_run, exit_on_failure)
    if not loaded:
        return True
    store_obj, purchases, ignores = loaded

    # Update each purchase
    logger.log_info("Starting to update purchases for %s" % store_obj.get_type())
    for purchase in purchases:
        success = _update_purchase(
            store_obj = store_obj,
            purchase = purchase,
            ignores = ignores,
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            keys = keys,
            force = force,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Should be successful
    return True

############################################################

# Get a store's purchases, or None when they cannot be listed, naming the store in skipped_stores
def get_game_store_purchases(
    store_obj,
    skipped_stores = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Skip a store with no saved sign-in, rather than running its tool to fail
    purchases = None
    if not store_obj.has_saved_login():
        logger.log_warning("Skipping %s purchases: not signed in. To sign in: %s" %
            (store_obj.get_type(), store_obj.get_login_hint()))
    else:
        logger.log_info("Retrieving purchases for %s" % store_obj.get_type())
        purchases = store_obj.get_latest_purchases(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if purchases is None:
            logger.log_warning("Skipping %s purchases: they could not be listed, usually because the sign-in expired. To sign in again: %s" %
                (store_obj.get_type(), store_obj.get_login_hint()))
    if purchases is None and skipped_stores is not None:
        skipped_stores.append(store_obj.get_type())
    return purchases

# Fetch the store's purchases once, import the new ones and update the known ones; True when the store is skipped for no sign-in
def build_game_store_purchases(
    game_supercategory,
    game_category,
    game_subcategory,
    keys = None,
    force = False,
    skipped_stores = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store
    store_obj = stores.get_store_by_categories(game_supercategory, game_category, game_subcategory)
    if not store_obj or not store_obj.can_import_purchases():
        return True
    logger.log_info("Building store purchases [Category: '%s', Subcategory: '%s'] ..." %
        (game_category, game_subcategory))

    # Get purchases once for both the import and the update
    purchases = get_game_store_purchases(
        store_obj = store_obj,
        skipped_stores = skipped_stores,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if purchases is None:
        return True

    # Import new purchases, then update known ones
    selection = {
        "game_supercategory": game_supercategory,
        "game_category": game_category,
        "game_subcategory": game_subcategory,
        "purchases": purchases,
        "verbose": verbose,
        "pretend_run": pretend_run,
        "exit_on_failure": exit_on_failure}
    if not import_game_store_purchases(**selection):
        return False
    return update_game_store_purchases(keys = keys, force = force, **selection)

# Build store purchases for one category's chosen subcategories; stops at the first failure
def _build_category_store_purchases(
    game_supercategory,
    game_category,
    selected_subcategories = None,
    keys = None,
    force = False,
    skipped_stores = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    category_subcategories = config.subcategory_map[game_category]
    if selected_subcategories:
        category_subcategories = [sc for sc in category_subcategories if sc in selected_subcategories]
    for game_subcategory in category_subcategories:
        success = build_game_store_purchases(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            keys = keys,
            force = force,
            skipped_stores = skipped_stores,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Build store purchases for the chosen ROM categories, then warn which stores were skipped
def build_all_game_store_purchases(
    keys = None,
    categories = None,
    subcategories = None,
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    selected_categories = config.Category.from_list(categories) if categories else config.Category.members()
    selected_subcategories = config.Subcategory.from_list(subcategories) if subcategories else None
    skipped_stores = []
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in selected_categories:
            success = _build_category_store_purchases(
                game_supercategory = game_supercategory,
                game_category = game_category,
                selected_subcategories = selected_subcategories,
                keys = keys,
                force = force,
                skipped_stores = skipped_stores,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

    # List the stores that were left out
    if skipped_stores:
        logger.log_warning("Store purchases skipped for: %s" % ", ".join(str(store_type) for store_type in skipped_stores))
    return True

############################################################

# The game's folder under the output dir, laid out like the locker, or its locker folder when no output dir is given
def _get_purchase_output_dir(game_info, output_dir = None):
    if output_dir:
        output_offset = environment.get_locker_gaming_files_offset(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name())
        return paths.join_paths(os.path.realpath(output_dir), output_offset)
    return environment.get_locker_gaming_files_dir(
        game_supercategory = game_info.get_supercategory(),
        game_category = game_info.get_category(),
        game_subcategory = game_info.get_subcategory(),
        game_name = game_info.get_name())

# Download the store's latest build of the game into the output dir, named with its version
def _download_latest_build(
    store_obj,
    game_info,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store info
    store_info_identifier = game_info.get_store_info_identifier()
    store_download_identifier = game_info.get_store_download_identifier()
    store_branchid = game_info.get_store_branchid()

    # Get latest version
    latest_version = store_obj.get_latest_version(
        identifier = store_info_identifier,
        branch = store_branchid,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Download files
    success = store_obj.download(
        identifier = store_download_identifier,
        branch = store_branchid,
        output_dir = output_dir,
        output_name = "%s (%s)" % (game_info.get_name(), latest_version),
        clean_output = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Download the store's latest build into the locker folder or under the output dir; True when the store has no downloads
def download_game_store_purchase(
    game_info,
    output_dir = None,
    skip_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store
    store_obj = stores.get_store_by_platform(game_info.get_platform())
    if not store_obj:
        return False

    # Check if downloads supported
    if not store_obj.can_download_purchases():
        return True

    # Get output dir
    output_dir = _get_purchase_output_dir(game_info, output_dir)
    if skip_existing and paths.does_directory_contain_files(output_dir):
        return True

    # Download latest build
    return _download_latest_build(
        store_obj = store_obj,
        game_info = game_info,
        output_dir = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Download the store build of every store game in the collection, skipping other platforms; stops at the first failure
def download_all_game_store_purchases(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_info in gamecollection.iterate_rom_game_infos(verbose, exit_on_failure):
        if not stores.is_store_platform(game_info.get_platform()):
            continue
        success = download_game_store_purchase(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

############################################################

# Build the store purchases of each (supercategory, category, subcategory); quits at the first failure
def build_store_purchases_for_categories(
    categories,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory, game_category, game_subcategory in categories:
        success = build_game_store_purchases(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error(
                message = "Build of store purchases failed!",
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                quit_program = True)
