#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import system
import gameinfo
import collection
import arguments
import setup
import logger
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Build metadata files.")
parser.add_game_supercategory_argument()
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_game_name_argument()
parser.add_enum_argument(
    args = ("-m", "--generation_mode"),
    arg_type = config.GenerationModeType,
    default = config.GenerationModeType.STANDARD,
    description = "Generation mode")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Collect games to process
    games_to_process = []
    for game_supercategory, game_category, game_subcategory in gameinfo.IterateSelectedGameCategories(
        parser = parser,
        generation_mode = args.generation_mode):
        game_names = gameinfo.FindJsonGameNames(
            game_supercategory,
            game_category,
            game_subcategory)
        if args.game_name:
            game_names = [g for g in game_names if g == args.game_name]
        for game_name in game_names:
            metadata_file = environment.GetGameMetadataFile(game_category, game_subcategory)
            games_to_process.append((game_supercategory, game_category, game_subcategory, game_name, metadata_file))

    # Show preview
    if not args.no_preview:
        details = list(set([metadata_file for _, _, _, _, metadata_file in games_to_process]))
        if not prompts.prompt_for_preview("Build game metadata files", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Build metadata files
    for game_supercategory, game_category, game_subcategory, game_name, _ in games_to_process:
        success = collection.BuildGameMetadataEntry(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error(
                message = "Build of metadata file failed!",
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                game_name = game_name,
                quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
