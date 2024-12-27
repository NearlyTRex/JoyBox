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
import gameinfo
import system
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Analyze json files.")
parser.add_argument("-m", "--mode",
    choices=config.AnalyzeModeType.values(),
    default=config.AnalyzeModeType.ALL,
    type=config.AnalyzeModeType,
    action=config.EnumArgparseAction,
    help="Analyze mode type"
)
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Json lists
    json_files_no_files = []
    json_files_unplayable = []

    # Analyze json files
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:
            game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
            for game_name in gameinfo.FindAllGameNames(environment.GetJsonRomsMetadataRootDir(), game_category, game_subcategory):

                # Get json file
                json_file = environment.GetJsonRomMetadataFile(game_category, game_subcategory, game_name)

                # Get game info
                game_info = gameinfo.GameInfo(
                    json_file = json_file,
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
                system.Log(json_file)

    # List unplayable games
    if args.mode == config.AnalyzeModeType.ALL or args.mode == config.AnalyzeModeType.UNPLAYABLE_GAMES:
        if len(json_files_unplayable):
            system.LogInfo("Games marked as unplayable:")
            for json_file in json_files_unplayable:
                system.Log(json_file)

# Start
main()
