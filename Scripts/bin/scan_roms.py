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
import gameinfo
import collection
import metadata
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Scan roms.")
parser.add_source_type_argument()
parser.add_passphrase_type_argument()
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

    # Build metadata files
    system.Log("Building metadata files ...")
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:

            # Get scan path
            scan_game_path = environment.GetLockerGamingRomCategoryDir(
                game_category = game_category,
                game_subcategory = game_subcategory,
                source_type = args.source_type)

            # Build metadata
            if system.IsPathDirectory(scan_game_path):
                system.Log("Building metadata [Category: '%s', Subcategory: '%s'] ..." % (game_category, game_subcategory))
                collection.ScanForMetadataEntries(
                    game_dir = scan_game_path,
                    game_category = game_category,
                    game_subcategory = game_subcategory,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

    # Build json files
    system.Log("Building json files ...")
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:
            game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
            for game_name in gameinfo.FindAllGameNames(environment.GetJsonRomsMetadataRootDir(), game_category, game_subcategory):

                # Get scan path
                scan_game_path = environment.GetLockerGamingRomDir(
                    game_category = game_category,
                    game_subcategory = game_subcategory,
                    game_name = game_name,
                    source_type = args.source_type)

                # Build json
                collection.CreateGameJsonFile(
                    game_category = game_category,
                    game_subcategory = game_subcategory,
                    game_name = game_name,
                    game_root = scan_game_path,
                    passphrase = passphrase,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

    # Publish metadata files
    system.Log("Publishing metadata files ...")
    for game_category in config.Category.members():

        # Publish metadata
        success = collection.PublishMetadataEntries(
            game_category = game_category,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            system.LogErrorAndQuit("Publish of category '%s' failed" % game_category)

# Start
main()
