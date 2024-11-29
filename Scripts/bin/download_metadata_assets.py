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
parser = argparse.ArgumentParser(description="Download metadata assets.")
parser.add_argument("-a", "--asset_type",
    choices=config.asset_types_all,
    default=config.asset_type_video,
    help="Asset type"
)
parser.add_argument("-e", "--skip_existing", action="store_true", help="Skip existing files")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Download metadata assets
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:
            game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
            for game_name in gameinfo.FindAllGameNames(environment.GetJsonRomsMetadataRootDir(), game_category, game_subcategory):

                # Download metadata asset
                system.Log("Downloading metadata assets for %s - %s..." % (game_platform, game_name))
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
