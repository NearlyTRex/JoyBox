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
import collection
import gameinfo
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Update metadata entries.")
parser.add_argument("-c", "--game_category", type=str, help="Game category")
parser.add_argument("-s", "--game_subcategory", type=str, help="Game subcategory")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
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
            system.Log("Updating metadata entry for %s - %s..." % (game_platform, game_name))
            collection.UpdateMetadataEntry(
                game_category = args.game_category,
                game_subcategory = args.game_subcategory,
                game_name = game_name,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

    # Specific category/all subcategories in that category
    elif args.game_category:
        for game_subcategory in config.game_subcategories[args.game_category]:
            game_platform = gameinfo.DeriveGamePlatformFromCategories(args.game_category, game_subcategory)
            for game_name in gameinfo.FindAllGameNames(environment.GetJsonRomsMetadataRootDir(), args.game_category, game_subcategory):

                # Update metadata entry
                system.Log("Updating metadata entry for %s - %s..." % (game_platform, game_name))
                collection.UpdateMetadataEntry(
                    game_category = args.game_category,
                    game_subcategory = game_subcategory,
                    game_name = game_name,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

    # All categories/subcategories
    else:
        for game_category in config.game_categories:
            for game_subcategory in config.game_subcategories[game_category]:
                game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
                for game_name in gameinfo.FindAllGameNames(environment.GetJsonRomsMetadataRootDir(), game_category, game_subcategory):

                    # Update metadata entry
                    system.Log("Updating metadata entry for %s - %s..." % (game_platform, game_name))
                    collection.UpdateMetadataEntry(
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        verbose = args.verbose,
                        pretend_run = args.pretend_run,
                        exit_on_failure = args.exit_on_failure)

# Start
main()
