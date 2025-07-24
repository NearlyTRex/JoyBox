#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import gameinfo
import system
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Analyze json files.")
parser.add_enum_argument(
    args = ("-m", "--mode"),
    arg_type = config.AnalyzeModeType,
    default = config.AnalyzeModeType.ALL,
    description = "Analyze mode type")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Json lists
    json_files_no_files = []
    json_files_unplayable = []

    # Analyze json files
    for game_supercategory in config.Supercategory.members():
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
                game_names = gameinfo.FindJsonGameNames(
                    game_supercategory,
                    game_category,
                    game_subcategory)
                for game_name in game_names:

                    # Get game info
                    game_info = gameinfo.GameInfo(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        verbose = args.verbose,
                        pretend_run = args.pretend_run,
                        exit_on_failure = args.exit_on_failure)
                    game_files = game_info.get_files()

                    # No files
                    if isinstance(game_files, list) and len(game_files) == 0:
                        json_files_no_files.append(json_file)

                    # Unplayable
                    if game_info.is_playable() == False:
                        json_files_unplayable.append(json_file)

    # List games with no files
    if args.mode == config.AnalyzeModeType.ALL or args.mode == config.AnalyzeModeType.MISSING_GAME_FILES:
        if len(json_files_no_files):
            system.LogInfo("Games with no files:")
            for json_file in json_files_no_files:
                system.LogInfo(json_file)

    # List unplayable games
    if args.mode == config.AnalyzeModeType.ALL or args.mode == config.AnalyzeModeType.UNPLAYABLE_GAMES:
        if len(json_files_unplayable):
            system.LogInfo("Games marked as unplayable:")
            for json_file in json_files_unplayable:
                system.LogInfo(json_file)

# Start
main()
