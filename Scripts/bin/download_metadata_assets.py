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
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Download metadata assets.")
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_enum_argument(
    args = ("-t", "--asset_type"),
    arg_type = config.AssetType,
    description = "Asset type")
parser.add_boolean_argument(args = ("-e", "--skip_existing"), description = "Skip existing files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Specific category/subcategory
    if args.game_category and args.game_subcategory:
        game_platform = gameinfo.DeriveGamePlatformFromCategories(args.game_category, args.game_subcategory)
        for game_name in gameinfo.FindAllGameNames(environment.GetJsonRomsMetadataRootDir(), args.game_category, args.game_subcategory):

            # Download metadata asset
            system.LogInfo("Downloading metadata assets for %s - %s..." % (game_platform, game_name))
            collection.DownloadMetadataAsset(
                game_category = args.game_category,
                game_subcategory = args.game_subcategory,
                game_name = game_name,
                asset_url = None,
                asset_type = args.asset_type,
                skip_existing = args.skip_existing,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

    # Specific category/all subcategories in that category
    elif args.game_category:
        for game_subcategory in config.subcategory_map[args.game_category]:
            game_platform = gameinfo.DeriveGamePlatformFromCategories(args.game_category, game_subcategory)
            for game_name in gameinfo.FindAllGameNames(environment.GetJsonRomsMetadataRootDir(), args.game_category, game_subcategory):

                # Download metadata asset
                system.LogInfo("Downloading metadata assets for %s - %s..." % (game_platform, game_name))
                collection.DownloadMetadataAsset(
                    game_category = args.game_category,
                    game_subcategory = game_subcategory,
                    game_name = game_name,
                    asset_url = None,
                    asset_type = args.asset_type,
                    skip_existing = args.skip_existing,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

    # All categories/subcategories
    else:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
                for game_name in gameinfo.FindAllGameNames(environment.GetJsonRomsMetadataRootDir(), game_category, game_subcategory):

                    # Download metadata asset
                    system.LogInfo("Downloading metadata assets for %s - %s..." % (game_platform, game_name))
                    collection.DownloadMetadataAsset(
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        asset_url = None,
                        asset_type = args.asset_type,
                        skip_existing = args.skip_existing,
                        verbose = args.verbose,
                        pretend_run = args.pretend_run,
                        exit_on_failure = args.exit_on_failure)

# Start
main()
