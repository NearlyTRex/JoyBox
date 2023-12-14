#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import metadata
import cache
import setup
import gui
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Cache game files.")
parser.add_argument("path", help="Input path")
parser.add_argument("-k", "--keep_setup_files", action="store_true", help="Keep setup files")
parser.add_argument("-f", "--force_cache_refresh", action="store_true", help="Force refresh of cached files")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Get game file
    game_file = args.path
    if os.path.isdir(args.path):
        game_file = metadata.FindBestGameFile(args.path)

    # Get game categories
    game_supercategory, game_category, game_subcategory = metadata.DeriveMetadataCategoriesFromFile(game_file)

    # Check metadata categories
    invalid_supercategory = (game_supercategory != config.game_supercategory_roms)
    invalid_category = (game_category == None)
    invalid_subcategory = (game_subcategory == None)
    if invalid_supercategory or invalid_category or invalid_subcategory:
        gui.DisplayErrorPopup(
            title_text = "Unable to recognize game categories",
            message_text = "Unable to recognize game categories from path %s" % args.path)

    # Get game platform
    game_platform = metadata.DeriveMetadataPlatform(game_category, game_subcategory)
    game_name = metadata.DeriveGameNameFromPath(game_file)
    if not game_platform or not game_name:
        gui.DisplayErrorPopup(
            title_text = "Unable to derive game platform or name",
            message_text = "Unable to derive game platform or name from path %s" % args.path)

    # Force cache refresh
    if args.force_cache_refresh:
        cache.RemoveGameFromCache(
            game_platform = game_platform,
            game_name = game_name,
            game_file = game_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Get game artwork
    game_artwork = environment.GetSyncedGameAssetFile(
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        asset_type = config.asset_type_boxfront)

    # Install game to cache
    cache.InstallGameToCache(
        game_platform = game_platform,
        game_name = game_name,
        game_file = game_file,
        game_artwork = game_artwork,
        keep_setup_files = args.keep_setup_files,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Start
main()
