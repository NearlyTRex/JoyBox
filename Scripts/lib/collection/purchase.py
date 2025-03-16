# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import gameinfo
import stores
from . import metadata
from . import jsondata

############################################################

# Import store purchases
def ImportStorePurchases(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for store_type in config.StoreType.members():

        # Get store obj
        store_obj = stores.GetStoreByType(store_type)
        if not store_obj:
            continue

        # Check if purchases can be imported
        if not store_obj.CanImportPurchases():
            continue

        # Login
        store_obj.Login(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Get all purchases
        purchases = store_obj.GetLatestPurchases(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not purchases:
            return False

        # Get all ignores
        ignores = jsondata.GetGameJsonIgnoreEntries(
            game_supercategory = store_obj.GetSupercategory(),
            game_category = store_obj.GetCategory(),
            game_subcategory = store_obj.GetSubcategory(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Import each purchase
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
            info_identifier = store_obj.GetInfoIdentifier(purchase)
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
                verbose = verbose,
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
                jsondata.AddGameJsonIgnoreEntry(
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
            success = jsondata.CreateJsonFile(
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
            success = metadata.CreateMetadataEntry(
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
