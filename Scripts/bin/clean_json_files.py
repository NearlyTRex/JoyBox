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
parser = arguments.ArgumentParser(description = "Clean json files.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Clean json files
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:
            game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
            for game_name in gameinfo.FindAllGameNames(environment.GetJsonRomsMetadataRootDir(), game_category, game_subcategory):

                # Get json file
                json_file = environment.GetJsonRomMetadataFile(game_category, game_subcategory, game_name)

                # Clean json file
                system.CleanJsonFile(
                    src = json_file,
                    sort_keys = True,
                    remove_empty_values = True,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

# Start
main()
