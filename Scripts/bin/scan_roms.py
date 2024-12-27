#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import gameinfo
import collection
import metadata
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Scan roms.")
parser.add_argument("-e", "--source_type",
    choices=config.SourceType.values(),
    default=config.SourceType.REMOTE,
    type=config.SourceType,
    action=config.EnumArgparseAction,
    help="Source type"
)
parser.add_argument("-t", "--passphrase_type",
    choices=config.PassphraseType.values(),
    default=config.PassphraseType.NONE,
    type=config.PassphraseType,
    action=config.EnumArgparseAction,
    help="Passphrase type"
)
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
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
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:

            # Get scan path
            scan_game_path = environment.GetLockerGamingRomCategoryDir(
                game_category = game_category,
                game_subcategory = game_subcategory,
                source_type = args.source_type)

            # Build metadata
            if os.path.isdir(scan_game_path):
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
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:
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
    for game_category in config.game_categories:

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
