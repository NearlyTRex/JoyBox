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
parser = arguments.ArgumentParser(description = "Build json files.")
parser.add_input_path_argument()
parser.add_game_supercategory_argument()
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_game_name_argument()
parser.add_enum_argument(
    args = ("-l", "--source_type"),
    arg_type = config.SourceType,
    default = config.SourceType.REMOTE,
    description = "Source type")
parser.add_enum_argument(
    args = ("-m", "--generation_mode"),
    arg_type = config.GenerationModeType,
    default = config.GenerationModeType.STANDARD,
    description = "Generation mode")
parser.add_enum_argument(
    args = ("-t", "--locker_type"),
    arg_type = config.LockerType,
    description = "Locker type")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Collect games to process
    games_to_process = []
    for game_supercategory, game_category, game_subcategory in gameinfo.IterateSelectedGameCategories(
        parser = parser,
        generation_mode = args.generation_mode):
        game_names = gameinfo.FindLockerGameNames(
            game_supercategory,
            game_category,
            game_subcategory,
            args.source_type)
        if args.game_name:
            game_names = [g for g in game_names if g == args.game_name]
        for game_name in game_names:
            game_root = parser.get_input_path(check_exists = False)
            json_file = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name)
            games_to_process.append((game_supercategory, game_category, game_subcategory, game_name, game_root, json_file))

    # Show preview
    if not args.no_preview:
        details = [json_file for _, _, _, _, _, json_file in games_to_process]
        if not prompts.prompt_for_preview("Build game JSON files (source: %s)" % args.source_type, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Build json files
    for game_supercategory, game_category, game_subcategory, game_name, game_root, _ in games_to_process:
        success = collection.BuildGameJsonFile(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            game_root = game_root,
            locker_type = args.locker_type,
            source_type = args.source_type,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error(
                message = "Build of json file failed!",
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                game_name = game_name,
                quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
