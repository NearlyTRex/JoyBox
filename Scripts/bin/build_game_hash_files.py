#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import collection
import gameinfo
import arguments
import setup
import logger
import prompts
import paths

# Parse arguments
parser = arguments.ArgumentParser(description = "Build file hashes.")
parser.add_input_path_argument()
parser.add_game_supercategory_argument()
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    description = "Locker type")
parser.add_enum_argument(
    args = ("-m", "--generation_mode"),
    arg_type = config.GenerationModeType,
    default = config.GenerationModeType.STANDARD,
    description = "Generation mode")
parser.add_string_argument(
    args = ("-b", "--locker_base_dir"),
    default = None,
    description = "Locker base directory (overrides default locker path)")
parser.add_boolean_argument(
    args = ("-d", "--delete_missing"),
    description = "Delete hash entries for files that no longer exist")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get locker base dir
    locker_base_dir = paths.expand_path(args.locker_base_dir) if args.locker_base_dir else None

    # Collect games to process
    games_to_process = []
    for game_info in gameinfo.iterate_selected_game_infos(
        parser = parser,
        generation_mode = args.generation_mode,
        locker_type = args.locker_type,
        locker_base_dir = locker_base_dir,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure):
        if parser.get_input_path(check_exists = False):
            game_root = parser.get_input_path(check_exists = False)
        elif locker_base_dir:
            game_offset = environment.get_locker_gaming_files_offset(
                game_info.get_supercategory(),
                game_info.get_category(),
                game_info.get_subcategory(),
                game_info.get_name())
            game_root = paths.join_paths(locker_base_dir, config.LockerFolderType.GAMING, game_offset)
        else:
            game_root = environment.get_locker_gaming_files_dir(
                game_info.get_supercategory(),
                game_info.get_category(),
                game_info.get_subcategory(),
                game_info.get_name(),
                args.locker_type)
        games_to_process.append((game_info, game_root))

    # Show preview
    if not args.no_preview:
        details = [game_root for _, game_root in games_to_process]
        if not prompts.prompt_for_preview("Build game hash files", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Build hash files
    for game_info, game_root in games_to_process:
        success = collection.build_hash_files(
            game_info = game_info,
            game_root = game_root,
            locker_type = args.locker_type,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error(
                message = "Build of hash files failed!",
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                game_name = game_info.get_name(),
                quit_program = True)

    # Clean missing hash entries
    if args.delete_missing:
        locker_root = paths.join_paths(locker_base_dir, config.LockerFolderType.GAMING) if locker_base_dir else environment.get_locker_gaming_root_dir(args.locker_type)
        subcategories_cleaned = set()
        for game_info, _ in games_to_process:
            subcategory_key = (game_info.get_supercategory(), game_info.get_category(), game_info.get_subcategory())
            if subcategory_key in subcategories_cleaned:
                continue
            subcategories_cleaned.add(subcategory_key)
            success = collection.clean_missing_hash_entries(
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                locker_root = locker_root,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if not success:
                logger.log_error(
                    message = "Clean of missing hash entries failed!",
                    game_supercategory = game_info.get_supercategory(),
                    game_category = game_info.get_category(),
                    game_subcategory = game_info.get_subcategory(),
                    quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
