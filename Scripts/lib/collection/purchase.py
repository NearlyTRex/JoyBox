# Imports
import os
import sys

# Local imports
import config
import system
import logger
import paths
import prompts
import serialization
import environment
import gameinfo
import stores
from .metadata import CreateGameMetadataEntry
from .metadata import UpdateGameMetadataEntry
from .jsondata import GetGameJsonIgnoreEntries
from .jsondata import AddGameJsonIgnoreEntry
from .jsondata import CreateGameJsonFile
from .jsondata import UpdateGameJsonFile

############################################################

# Login game store
def LoginGameStore(
    game_supercategory,
    game_category,
    game_subcategory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    stores.GetStoreByCategories(
        store_supercategory = game_supercategory,
        store_category = game_category,
        store_subcategory = game_subcategory,
        login = True)
    return True

# Login all game stores
def LoginAllGameStores(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                success = LoginGameStore(
                    game_supercategory = game_supercategory,
                    game_category = game_category,
                    game_subcategory = game_subcategory,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return False

    # Should be successful
    return True

############################################################

# Import game store purchases
def ImportGameStorePurchases(
    game_supercategory,
    game_category,
    game_subcategory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store
    store_obj = stores.GetStoreByCategories(game_supercategory, game_category, game_subcategory)
    if not store_obj:
        return True

    # Check if purchases can be imported
    if not store_obj.can_import_purchases():
        return True

    # Get all purchases
    logger.log_info("Retrieving purchases for %s" % store_obj.get_type())
    purchases = store_obj.get_latest_purchases(
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not purchases:
        return True

    # Get all ignores
    logger.log_info("Fetching ignore entries for %s" % store_obj.get_type())
    ignores = GetGameJsonIgnoreEntries(
        game_supercategory = store_obj.get_supercategory(),
        game_category = store_obj.get_category(),
        game_subcategory = store_obj.get_subcategory(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Import each purchase
    logger.log_info("Starting to import purchases for %s" % store_obj.get_type())
    for purchase in purchases:
        purchase_appid = purchase.get_value(config.json_key_store_appid)
        purchase_appname = purchase.get_value(config.json_key_store_appname)
        purchase_appurl = purchase.get_value(config.json_key_store_appurl)
        purchase_name = purchase.get_value(config.json_key_store_name)
        purchase_identifiers = [
            purchase_appid,
            purchase_appname,
            purchase_appurl
        ]

        # Get info identifier
        info_identifier = purchase.get_value(store_obj.get_info_identifier_key())
        if not info_identifier:
            continue
        if info_identifier in ignores.keys():
            continue

        # Skip if json file already exists
        json_matches = serialization.search_json_files(
            src = environment.get_json_metadata_dir(
                game_supercategory = store_obj.get_supercategory(),
                game_category = store_obj.get_category(),
                game_subcategory = store_obj.get_subcategory()),
            search_values = purchase_identifiers,
            search_keys = config.json_keys_store_appdata,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if len(json_matches):
            continue

        # Determine if this should be imported
        logger.log_info("Found new potential entry:")
        if purchase_appid:
            logger.log_info(" - Appid:\t" + purchase_appid)
        if purchase_appname:
            logger.log_info(" - Appname:\t" + purchase_appname)
        if purchase_appurl:
            logger.log_info(" - Appurl:\t" + purchase_appurl)
        if purchase_name:
            logger.log_info(" - Name:\t" + purchase_name)
        should_import = prompts.prompt_for_value("Import this? (n to skip, i to ignore)", default_value = "y")
        if should_import.lower() == "n":
            continue

        # Add to ignore
        if should_import.lower() == "i":
            AddGameJsonIgnoreEntry(
                game_supercategory = store_obj.get_supercategory(),
                game_category = store_obj.get_category(),
                game_subcategory = store_obj.get_subcategory(),
                game_identifier = info_identifier,
                game_name = purchase_name,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            continue

        # Prompt for entry name
        default_name = gameinfo.DeriveGameNameFromRegularName(purchase_name)
        entry_name = prompts.prompt_for_value("Choose entry name", default_value = default_name)

        # Get appurl if possible
        if not purchase_appurl and purchase_name:
            purchase_appurl = store_obj.get_latest_url(
                identifier = purchase_name,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if purchase_appurl:
                purchase.set_value(config.json_key_store_appurl, purchase_appurl)

        # Create json file
        success = CreateGameJsonFile(
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
        success = CreateGameMetadataEntry(
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

    # Should be successful
    return True

############################################################

# Update game store purchases
def UpdateGameStorePurchases(
    game_supercategory,
    game_category,
    game_subcategory,
    locker_type = None,
    source_type = None,
    keys = [],
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store
    store_obj = stores.GetStoreByCategories(game_supercategory, game_category, game_subcategory)
    if not store_obj:
        return True

    # Check if purchases can be imported
    if not store_obj.can_import_purchases():
        return True

    # Get all purchases
    logger.log_info("Retrieving purchases for %s" % store_obj.get_type())
    purchases = store_obj.get_latest_purchases(
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not purchases:
        return True

    # Get all ignores
    logger.log_info("Fetching ignore entries for %s" % store_obj.get_type())
    ignores = GetGameJsonIgnoreEntries(
        game_supercategory = store_obj.get_supercategory(),
        game_category = store_obj.get_category(),
        game_subcategory = store_obj.get_subcategory(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Update each purchase
    logger.log_info("Starting to update purchases for %s" % store_obj.get_type())
    for purchase in purchases:
        purchase_appid = purchase.get_value(config.json_key_store_appid)
        purchase_appname = purchase.get_value(config.json_key_store_appname)
        purchase_appurl = purchase.get_value(config.json_key_store_appurl)
        purchase_name = purchase.get_value(config.json_key_store_name)
        purchase_identifiers = [
            purchase_appid,
            purchase_appname,
            purchase_appurl
        ]

        # Get info identifier
        info_identifier = purchase.get_value(store_obj.get_info_identifier_key())
        if not info_identifier:
            continue
        if info_identifier in ignores.keys():
            continue

        # Find matching json file
        json_matches = serialization.search_json_files(
            src = environment.get_json_metadata_dir(
                game_supercategory = store_obj.get_supercategory(),
                game_category = store_obj.get_category(),
                game_subcategory = store_obj.get_subcategory()),
            search_values = purchase_identifiers,
            search_keys = config.json_keys_store_appdata,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        json_file = None
        if len(json_matches):
            json_file = json_matches[0]
        if not paths.is_path_file(json_file):
            continue

        # Get game name
        game_name = paths.get_filename_basename(json_file)

        # Get game root
        game_root = environment.get_locker_gaming_files_dir(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            source_type = source_type)

        # Update json file
        success = UpdateGameJsonFile(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            game_root = game_root,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to update json file for game '%s'" % game_name)
            return False

        # Update metadata entry
        success = UpdateGameMetadataEntry(
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

    # Should be successful
    return True

############################################################

# Build game store purchase
def BuildGameStorePurchases(
    game_supercategory,
    game_category,
    game_subcategory,
    locker_type = None,
    source_type = None,
    keys = [],
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Log categories
    logger.log_info("Building store purchases [Category: '%s', Subcategory: '%s'] ..." %
        (game_category, game_subcategory))

    # Import store purchases
    success = ImportGameStorePurchases(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Update store purchases
    success = UpdateGameStorePurchases(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        locker_type = locker_type,
        source_type = source_type,
        keys = keys,
        force = force,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Build all game store purchases
def BuildAllGameStorePurchases(
    locker_type = None,
    source_type = None,
    keys = [],
    categories = None,
    subcategories = None,
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    selected_categories = config.Category.from_list(categories) if categories else config.Category.members()
    selected_subcategories = config.Subcategory.from_list(subcategories) if subcategories else None
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in selected_categories:
            category_subcategories = config.subcategory_map[game_category]
            if selected_subcategories:
                category_subcategories = [sc for sc in category_subcategories if sc in selected_subcategories]
            for game_subcategory in category_subcategories:
                success = BuildGameStorePurchases(
                    game_supercategory = game_supercategory,
                    game_category = game_category,
                    game_subcategory = game_subcategory,
                    locker_type = locker_type,
                    source_type = source_type,
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

# Download game store purchase
def DownloadGameStorePurchase(
    game_info,
    output_dir = None,
    skip_existing = False,
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store
    store_obj = stores.GetStoreByPlatform(game_info.get_platform())
    if not store_obj:
        return False

    # Check if downloads supported
    if not store_obj.can_download_purchases():
        return True

    # Get output dir
    if output_dir:
        output_offset = environment.get_locker_gaming_files_offset(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name())
        output_dir = paths.join_paths(os.path.realpath(output_dir), output_offset)
    else:
        output_dir = environment.get_locker_gaming_files_dir(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name())
    if skip_existing and paths.does_directory_contain_files(output_dir):
        return True

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

# Download all game store purchases
def DownloadAllGameStorePurchases(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_names = gameinfo.FindJsonGameNames(
                    game_supercategory,
                    game_category,
                    game_subcategory)
                for game_name in game_names:
                    game_info = gameinfo.GameInfo(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    success = DownloadGameStorePurchases(
                        game_info = game_info,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

############################################################
