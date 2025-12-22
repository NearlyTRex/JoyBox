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
import logger

# Parse arguments
parser = arguments.ArgumentParser(description = "Clean json files.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Collect json files to process
    json_files_to_process = []
    for game_supercategory in config.Supercategory.members():
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
                game_names = gameinfo.FindJsonGameNames(
                    game_supercategory,
                    game_category,
                    game_subcategory)
                for game_name in game_names:

                    # Get json file
                    json_file = environment.GetGameJsonMetadataFile(game_supercategory, game_category, game_subcategory, game_name)
                    if not system.IsPathFile(json_file):
                        continue
                    json_files_to_process.append(json_file)

    # Show preview
    if not args.no_preview:
        if not system.PromptForPreview("Clean game JSON files (sort keys, remove empty values)", json_files_to_process):
            logger.log_warning("Operation cancelled by user")
            return

    # Clean json files
    for json_file in json_files_to_process:
        system.CleanJsonFile(
            src = json_file,
            sort_keys = True,
            remove_empty_values = True,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.RunMain(main)
