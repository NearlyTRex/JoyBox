#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import collection
import gameinfo
import arguments
import metadata
import stores
import manifest
import setup
import ini

# Parse arguments
parser = arguments.ArgumentParser(description = "Scan roms files.")
parser.add_enum_argument(
    args = ("-l", "--source_type"),
    arg_type = config.SourceType,
    default = config.SourceType.REMOTE,
    description = "Source type")
parser.add_enum_argument(
    args = ("-t", "--passphrase_type"),
    arg_type = config.PassphraseType,
    description = "Passphrase type")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get passphrase
    passphrase = None
    if args.passphrase_type == config.PassphraseType.GENERAL:
        passphrase = ini.GetIniValue("UserData.Protection", "general_passphrase")
    elif args.passphrase_type == config.PassphraseType.LOCKER:
        passphrase = ini.GetIniValue("UserData.Protection", "locker_passphrase")

    # Load manifest
    system.LogInfo("Loading manifest ...")
    store_manifest = manifest.Manifest()
    store_manifest.load(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

    # Import store purchases
    system.LogInfo("Importing store purchases ...")
    for store_type in config.StoreType.members():
        store_obj = stores.GetStoreByType(store_type)
        if store_obj:
            if not store_obj.CanImportPurchases():
                continue

            # Import manifest
            store_obj.LoadManifest(store_manifest,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

            # Login
            store_obj.Login(
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

            # Import purchases
            store_obj.ImportPurchases(
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

    # Build metadata files
    system.LogInfo("Building metadata files ...")
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
                game_names = gameinfo.FindLockerGameNames(
                    game_supercategory,
                    game_category,
                    game_subcategory,
                    args.source_type)
                for game_name in game_names:

                    # Get scan path
                    scan_game_path = environment.GetLockerGamingFilesDir(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        source_type = args.source_type)

                    # Build metadata
                    if system.IsPathDirectory(scan_game_path):
                        system.LogInfo("Building metadata [Category: '%s', Subcategory: '%s', Name: '%s'] ..." %
                            (game_category, game_subcategory, game_name))
                        collection.ScanForMetadataEntries(
                            game_supercategory = game_supercategory,
                            game_category = game_category,
                            game_subcategory = game_subcategory,
                            game_root = scan_game_path,
                            verbose = args.verbose,
                            pretend_run = args.pretend_run,
                            exit_on_failure = args.exit_on_failure)

    # Build json files
    system.LogInfo("Building json files ...")
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
                game_names = gameinfo.FindLockerGameNames(
                    game_supercategory,
                    game_category,
                    game_subcategory,
                    args.source_type)
                for game_name in game_names:

                    # Get scan path
                    scan_game_path = environment.GetLockerGamingFilesDir(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        source_type = args.source_type)

                    # Build json
                    collection.CreateGameJsonFile(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        game_root = scan_game_path,
                        passphrase = passphrase,
                        verbose = args.verbose,
                        pretend_run = args.pretend_run,
                        exit_on_failure = args.exit_on_failure)

    # Publish metadata files
    system.LogInfo("Publishing metadata files ...")
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():

            # Publish metadata
            success = collection.PublishMetadataEntries(
                game_supercategory = game_supercategory,
                game_category = game_category,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if not success:
                system.LogError("Publish of category '%s' failed" % game_category, quit_program = True)

# Start
main()
