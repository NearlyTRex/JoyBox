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
import launcher
import setup
import ini

# Setup argument parser
parser = argparse.ArgumentParser(description="Launch random ROM.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-c", "--category", type=str, help="Rom category")
parser.add_argument("-s", "--subcategory", type=str, help="Rom subcategory")
parser.add_argument("-f", "--force_cache_refresh", action="store_true", help="Force refresh of cached files")

# Parse arguments
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")
    fullscreen = ini.GetIniBoolValue("UserData.Flags", "fullscreen")

    # Get capture type
    capture_type = ini.GetIniValue("UserData.Capture", "capture_type")

    # Get category
    game_category = args.category
    if not game_category:
        game_category = random.choice(config.game_categories)

    # Check subcategory
    game_subcategory = args.subcategory
    if not game_subcategory:
        potential_subcategories = []
        for game_subcategory in config.game_subcategories[game_category]:
            if platforms.HasNoLauncher(DeriveGamePlatformFromCategories(game_category, game_subcategory)):
                potential_subcategories.append(game_subcategory)
        game_subcategory = random.choice(potential_subcategories)

    # Read metadata
    metadata_file = environment.GetMetadataFile(game_category, game_subcategory, config.metadata_format_gamelist)
    metadata_obj = metadata.Metadata()
    metadata_obj.import_from_gamelist_file(metadata_file)

    # Select random game entry
    random_game_entry = metadata_obj.get_random_entry()
    if not random_game_entry:
        print("Unable to select random game for launching")
        sys.exit(1)

    # Get json file
    json_file = environment.GetJsonRomMetadataFile(
        game_category = random_game_entry[config.metadata_key_category],
        game_subcategory = random_game_entry[config.metadata_key_subcategory],
        game_name = random_game_entry[config.metadata_key_game])

    # Force cache refresh
    if args.force_cache_refresh:
        cache.RemoveGameFromCache(
            game_platform = random_game_entry[config.metadata_key_platform],
            game_name = random_game_entry[config.metadata_key_game],
            game_file = json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Launch game
    launcher.LaunchGame(
        json_file = json_file,
        capture_type = capture_type,
        fullscreen = fullscreen,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Start
main()
