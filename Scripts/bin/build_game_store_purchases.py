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
parser = arguments.ArgumentParser(description = "Build store purchases.")
parser.add_game_supercategory_argument()
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_enum_argument(
    args = ("-l", "--source_type"),
    arg_type = config.SourceType,
    default = config.SourceType.REMOTE,
    description = "Source type")
parser.add_enum_argument(
    args = ("-t", "--locker_type"),
    arg_type = config.LockerType,
    description = "Locker type")
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

    # Collect categories to process
    categories_to_process = []
    for game_supercategory, game_category, game_subcategory in gameinfo.IterateSelectedGameCategories(
        parser = parser,
        generation_mode = args.generation_mode):
        categories_to_process.append((game_supercategory, game_category, game_subcategory))

    # Show preview
    if not args.no_preview:
        details = ["%s/%s/%s" % (sc, c, sub) for sc, c, sub in categories_to_process]
        if not prompts.prompt_for_preview("Build game store purchases (source: %s)" % args.source_type, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Build store purchases
    for game_supercategory, game_category, game_subcategory in categories_to_process:
        success = collection.BuildGameStorePurchases(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            locker_type = args.locker_type,
            source_type = args.source_type,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error(
                message = "Build of store purchases failed!",
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
