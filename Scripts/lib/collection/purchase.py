# Imports
import os
import sys

# Local imports
import config
import system
import environment
import gameinfo
import stores
from .metadata import CreateMetadataEntry
from .jsondata import GetGameJsonIgnoreEntries
from .jsondata import AddGameJsonIgnoreEntry
from .jsondata import CreateJsonFile
from .uploading import UploadGameFiles

############################################################

# Import store purchases
def ImportStorePurchases(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for store_type in config.StoreType.members():

        # Get store obj
        system.LogInfo("Getting store for %s" % store_type)
        store_obj = stores.GetStoreByType(store_type)
        if not store_obj:
            continue

        # Check if purchases can be imported
        if not store_obj.CanImportPurchases():
            continue

        # Login
        system.LogInfo("Logging into %s store" % store_type)
        store_obj.Login(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Get all purchases
        system.LogInfo("Retrieving purchases for %s" % store_type)
        purchases = store_obj.GetLatestPurchases(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not purchases:
            return True

        # Get all ignores
        system.LogInfo("Fetching ignore entries for %s" % store_type)
        ignores = GetGameJsonIgnoreEntries(
            game_supercategory = store_obj.GetSupercategory(),
            game_category = store_obj.GetCategory(),
            game_subcategory = store_obj.GetSubcategory(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Import each purchase
        system.LogInfo("Starting to import purchases for %s" % store_type)
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
            info_identifier = purchase.get_value(store_obj.GetInfoIdentifierKey())
            if not info_identifier:
                continue
            if info_identifier in ignores.keys():
                continue

            # Skip if json file already exists
            json_matches = system.SearchJsonFiles(
                src = environment.GetJsonMetadataDir(
                    game_supercategory = store_obj.GetSupercategory(),
                    game_category = store_obj.GetCategory(),
                    game_subcategory = store_obj.GetSubcategory()),
                search_values = purchase_identifiers,
                search_keys = config.json_keys_store_appdata,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if len(json_matches):
                continue

            # Determine if this should be imported
            system.LogInfo("Found new potential entry:")
            if purchase_appid:
                system.LogInfo(" - Appid:\t" + purchase_appid)
            if purchase_appname:
                system.LogInfo(" - Appname:\t" + purchase_appname)
            if purchase_appurl:
                system.LogInfo(" - Appurl:\t" + purchase_appurl)
            if purchase_name:
                system.LogInfo(" - Name:\t" + purchase_name)
            should_import = system.PromptForValue("Import this? (n to skip, i to ignore)", default_value = "n")
            if should_import.lower() == "n":
                continue

            # Add to ignore
            if should_import.lower() == "i":
                AddGameJsonIgnoreEntry(
                    game_supercategory = store_obj.GetSupercategory(),
                    game_category = store_obj.GetCategory(),
                    game_subcategory = store_obj.GetSubcategory(),
                    game_identifier = info_identifier,
                    game_name = purchase_name,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                continue

            # Prompt for entry name
            default_name = gameinfo.DeriveGameNameFromRegularName(purchase_name)
            entry_name = system.PromptForValue("Choose entry name", default_value = default_name)

            # Get appurl if necessary
            if not purchase_appurl and purchase_name:
                purchase_appurl = store_obj.GetLatestUrl(
                    identifier = purchase_name,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if purchase_appurl:
                    purchase.set_value(config.json_key_store_appurl, purchase_appurl)

            # Create json file
            success = CreateJsonFile(
                game_supercategory = store_obj.GetSupercategory(),
                game_category = store_obj.GetCategory(),
                game_subcategory = store_obj.GetSubcategory(),
                game_name = entry_name,
                initial_data = {store_obj.GetKey(): purchase.get_data_copy()},
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Unable to create json file for game '%s'" % entry_name)
                return False

            # Create metadata entry
            success = CreateMetadataEntry(
                game_supercategory = store_obj.GetSupercategory(),
                game_category = store_obj.GetCategory(),
                game_subcategory = store_obj.GetSubcategory(),
                game_name = entry_name,
                game_url = purchase_appurl,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Unable to add metadata entry for game '%s'" % entry_name)
                return False

    # Should be successful
    return True

############################################################

# Download store purchase
def DownloadStorePurchase(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    output_dir = None,
    skip_existing = False,
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get platform
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Get store
    store_obj = stores.GetStoreByPlatform(game_platform)
    if not store_obj:
        return False

    # Check if downloads supported
    if not store_obj.CanDownloadPurchases():
        return True

    # Get output dir
    if output_dir:
        output_offset = environment.GetLockerGamingFilesOffset(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name)
        output_dir = system.JoinPaths(os.path.realpath(output_dir), output_offset)
    else:
        output_dir = environment.GetLockerGamingFilesDir(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name)
    if skip_existing and system.DoesDirectoryContainFiles(output_dir):
        return True

    # Get json file path
    json_file_path = environment.GetJsonMetadataFile(game_supercategory, game_category, game_subcategory, game_name)
    if not system.DoesPathExist(json_file_path):
        return False

    # Read json data
    json_file_data = system.ReadJsonFile(
        src = json_file_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Create json data object
    json_obj = jsondata.JsonData(
        json_data = json_file_data,
        json_platform = game_platform)

    # Get store info
    store_info_identifier = json_obj.get_subvalue(store_obj.GetKey(), store_obj.GetInfoIdentifierKey())
    store_download_identifier = json_obj.get_subvalue(store_obj.GetKey(), store_obj.GetDownloadIdentifierKey())
    store_branch = json_obj.get_subvalue(store_obj.GetKey(), config.json_key_store_branchid)

    # Get latest version
    latest_version = store_obj.GetLatestVersion(
        identifier = store_info_identifier,
        branch = store_branch,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Download files
    success = store_obj.Download(
        identifier = store_download_identifier,
        branch = store_branch,
        output_dir = output_dir,
        output_name = "%s (%s)" % (game_name, latest_version),
        clean_output = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################

# Backup store purchase
def BackupStorePurchase(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    passphrase,
    skip_existing = False,
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Download files
    success = DownloadStorePurchase(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        output_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Upload files
    success = UploadGameFiles(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        game_root = tmp_dir_result,
        passphrase = passphrase,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Should be successful
    return True

############################################################
