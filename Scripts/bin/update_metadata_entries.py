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
parser = arguments.ArgumentParser(description = "Update metadata entries.")
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
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

            # Update metadata entry
            system.Log("Updating metadata entry for %s - %s..." % (game_platform.val(), game_name))
            collection.UpdateMetadataEntry(
                game_category = args.game_category,
                game_subcategory = args.game_subcategory,
                game_name = game_name,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

    # Specific category/all subcategories in that category
    elif args.game_category:
        for game_subcategory in config.subcategory_map[args.game_category]:
            game_platform = gameinfo.DeriveGamePlatformFromCategories(args.game_category, game_subcategory)
            for game_name in gameinfo.FindAllGameNames(environment.GetJsonRomsMetadataRootDir(), args.game_category, game_subcategory):

                # Update metadata entry
                system.Log("Updating metadata entry for %s - %s..." % (game_platform.val(), game_name))
                collection.UpdateMetadataEntry(
                    game_category = args.game_category,
                    game_subcategory = game_subcategory,
                    game_name = game_name,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

    # All categories/subcategories
    else:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
                for game_name in gameinfo.FindAllGameNames(environment.GetJsonRomsMetadataRootDir(), game_category, game_subcategory):

                    # Update metadata entry
                    system.Log("Updating metadata entry for %s - %s..." % (game_platform.val(), game_name))
                    collection.UpdateMetadataEntry(
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        verbose = args.verbose,
                        pretend_run = args.pretend_run,
                        exit_on_failure = args.exit_on_failure)

# Start
main()
