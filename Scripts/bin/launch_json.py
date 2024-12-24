#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse
import random

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import platforms
import launcher
import metadata
import cache
import setup
import gameinfo
import gui

# Setup argument parser
parser = argparse.ArgumentParser(description="Launch json game.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-i", "--input_file", type=str, help="Json file to launch")
parser.add_argument("-e", "--source_type",
    choices=config.SourceType.members(),
    default=config.SourceType.REMOTE,
    help="Source types"
)
parser.add_argument("-c", "--game_category", type=str, help="Game category")
parser.add_argument("-s", "--game_subcategory", type=str, help="Game subcategory")
parser.add_argument("-n", "--game_name", type=str, help="Game name")
parser.add_argument("-r", "--fill_with_random", action="store_true", help="Fill unspecified fields with random values")
parser.add_argument("-t", "--capture_type",
    choices=config.CaptureType.members(),
    default=config.CaptureType.NONE, help="Capture type"
)
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
parser.add_argument("-f", "--fullscreen", action="store_true", help="Enable fullscreen mode")
parser.add_argument("--force_cache_refresh", action="store_true", help="Force refresh of cached files")

# Parse arguments
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Json file to load
    json_file = None

    # Prefer input file if it was specified
    if args.input_file:
        if os.path.isfile(args.input_file):
            json_file = args.input_file
        else:
            json_file = os.path.join(environment.GetJsonRomsMetadataRootDir(), json_file)

    # Next use category values
    elif args.game_category and args.game_subcategory and args.game_name:
        json_file = environment.GetJsonRomMetadataFile(
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            game_name = args.game_name)

    # Finally, use random selection
    elif args.fill_with_random:

        # Get category
        game_category = args.game_category
        if not game_category:
            game_category = random.choice(config.game_categories)

        # Get subcategory
        game_subcategory = args.game_subcategory
        if not game_subcategory:
            potential_subcategories = []
            for potential_subcategory in config.game_subcategories[game_category]:
                potential_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, potential_subcategory)
                if not platforms.HasNoLauncher(potential_platform):
                    potential_subcategories.append(potential_subcategory)
            game_subcategory = random.choice(potential_subcategories)

        # Read metadata for this category/subcategory pair
        metadata_file = environment.GetMetadataFile(game_category, game_subcategory)
        metadata_obj = metadata.Metadata()
        metadata_obj.import_from_metadata_file(metadata_file)

        # Select random game entry
        random_game_entry = metadata_obj.get_random_entry()

        # Get json file
        if random_game_entry:
            json_file = environment.GetJsonRomMetadataFile(
                game_category = random_game_entry[config.metadata_key_category],
                game_subcategory = random_game_entry[config.metadata_key_subcategory],
                game_name = random_game_entry[config.metadata_key_game])

    # Check json file
    if not json_file:
        gui.DisplayErrorPopup(
            title_text = "No json file specified",
            message_text = "No json file was specified")
    if not os.path.isfile(json_file):
        gui.DisplayErrorPopup(
            title_text = "Json file not found",
            message_text = "Json file %s was not found" % json_file)

    # Get game info
    game_info = gameinfo.GameInfo(
        json_file = json_file,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

    # Check ability to launch
    if not game_info.is_playable():
        gui.DisplayErrorPopup(
            title_text = "Json file not launchable",
            message_text = "Json file '%s' is not launchable" % system.GetFilenameFile(json_file))

    # Force cache refresh
    if args.force_cache_refresh:
        cache.RemoveGameFromCache(
            game_info = game_info,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Launch game
    launcher.LaunchGame(
        game_info = game_info,
        source_type = args.source_type,
        capture_type = args.capture_type,
        fullscreen = args.fullscreen,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
main()
