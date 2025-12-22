#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import random

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import platforms
import collection
import metadata
import gameinfo
import arguments
import gui
import setup
import logger
import paths

# Setup argument parser
parser = arguments.ArgumentParser(description = "Launch json files.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-l", "--source_type"),
    arg_type = config.SourceType,
    default = config.SourceType.REMOTE,
    description = "Source type")
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_game_name_argument()
parser.add_boolean_argument(args = ("-r", "--fill_with_random"), description = "Fill unspecified fields with random values")
parser.add_enum_argument(
    args = ("-t", "--capture_type"),
    arg_type = config.CaptureType,
    description = "Capture type")
parser.add_boolean_argument(args = ("-f", "--fullscreen"), description = "Enable fullscreen mode")
parser.add_common_arguments()

# Parse arguments
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Json file to load
    json_file = None

    # Prefer input file if it was specified
    if args.input_path:
        json_file = parser.get_input_path()

    # Next use category values
    elif args.game_category and args.game_subcategory and args.game_name:
        json_file = environment.GetGameJsonMetadataFile(
            game_supercategory = config.Supercategory.ROMS,
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            game_name = args.game_name)

    # Finally, use random selection
    elif args.fill_with_random:

        # Get category
        game_category = args.game_category
        if not game_category:
            game_category = random.choice(config.Category.members())

        # Get subcategory
        game_subcategory = args.game_subcategory
        if not game_subcategory:
            potential_subcategories = []
            for potential_subcategory in config.subcategory_map[game_category]:
                potential_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, potential_subcategory)
                if not platforms.HasNoLauncher(potential_platform):
                    potential_subcategories.append(potential_subcategory)
            game_subcategory = random.choice(potential_subcategories)

        # Read metadata for this category/subcategory pair
        metadata_file = environment.GetGameMetadataFile(game_category, game_subcategory)
        metadata_obj = metadata.Metadata()
        metadata_obj.import_from_metadata_file(metadata_file)

        # Select random game entry
        random_game_entry = metadata_obj.get_random_entry()

        # Get json file
        if random_game_entry:
            json_file = environment.GetGameJsonMetadataFile(
                game_supercategory = config.Supercategory.ROMS,
                game_category = random_game_entry[config.metadata_key_category],
                game_subcategory = random_game_entry[config.metadata_key_subcategory],
                game_name = random_game_entry[config.metadata_key_game])

    # Check json file
    if not json_file:
        gui.DisplayErrorPopup(
            title_text = "No json file specified",
            message_text = "No json file was specified")
    if not paths.is_path_file(json_file):
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
            message_text = "Json file '%s' is not launchable" % paths.get_filename_file(json_file))

    # Launch game
    success = collection.LaunchGame(
        game_info = game_info,
        source_type = args.source_type,
        capture_type = args.capture_type,
        fullscreen = args.fullscreen,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        gui.DisplayErrorPopup(
            title_text = "Json file failed to launch",
            message_text = "Json file '%s' failed to launch" % paths.get_filename_file(json_file))

# Start
if __name__ == "__main__":
    system.RunMain(main)
