#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import metadata
import launcher
import setup
import ini

# Setup argument parser
parser = argparse.ArgumentParser(description="Launch random ROM.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-c", "--category", type=str, help="Rom category")
parser.add_argument("-s", "--subcategory", type=str, help="Rom subcategory")
parser.add_argument("-f", "--force_cache_refresh", action="store_true", help="Force refresh of cached files")
parser.add_argument("-c", "--capture_type",
    choices=[
        config.capture_type_none,
        config.capture_type_screenshot,
        config.capture_type_video,
    ],
    default=config.capture_type_none, help="Capture type"
)

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

    # Set filter options
    filter_options = {}
    filter_options[config.filter_launchable_only] = True

    # Get random game
    game_entry = metadata.ChooseRandomGame(
        rom_category = args.category,
        rom_subcategory = args.subcategory,
        filter_options = filter_options)
    if not game_entry:
        print("Unable to select random game for launching")
        sys.exit(1)

    # Force cache refresh
    if args.force_cache_refresh:
        cache.RemoveGameFromCache(
            game_platform = game_entry[config.metadata_key_platform],
            game_name = game_entry[config.metadata_key_game],
            game_file = game_entry[config.metadata_key_file],
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Launch game
    launcher.LaunchGame(
        game_platform = game_entry[config.metadata_key_platform],
        game_file = game_entry[config.metadata_key_file],
        capture_type = args.capture_type,
        fullscreen = fullscreen,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Start
main()
