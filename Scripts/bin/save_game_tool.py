#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import arguments
import collection
import gameinfo
import setup
import logger
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Save tool.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.SaveActionType,
    default = config.SaveActionType.PACK,
    description = "Save action type")
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_game_name_argument()
parser.add_enum_argument(
    args = ("-k", "--locker_type"),
    arg_type = config.LockerType,
    default = config.LockerType.ALL,
    description = "Locker type for backup upload")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Action handlers
    action_handlers = {
        config.SaveActionType.PACK: (collection.PackSave, "Packing of save failed!"),
        config.SaveActionType.UNPACK: (collection.UnpackSave, "Unpacking of save failed!"),
        config.SaveActionType.IMPORT: (collection.ImportGameSave, "Import of save failed!"),
        config.SaveActionType.EXPORT: (collection.ExportGameSave, "Export of save failed!"),
        config.SaveActionType.IMPORT_SAVE_PATHS: (collection.ImportGameSavePaths, "Import of save paths failed!"),
    }

    # Get handler for action
    handler, error_message = action_handlers.get(args.action, (None, None))
    if not handler:
        logger.log_error("Unknown action", quit_program = True)

    # Collect games to process
    games_to_process = []
    for game_info in gameinfo.iterate_selected_game_infos(
        parser = parser,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure):
        games_to_process.append(game_info)

    # Show preview
    if not args.no_preview:
        details = ["%s/%s/%s" % (g.get_category(), g.get_subcategory(), g.get_name()) for g in games_to_process]
        if not prompts.prompt_for_preview("Save game %s" % args.action, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Process games
    for game_info in games_to_process:
        handler_kwargs = {
            "game_info": game_info,
            "verbose": args.verbose,
            "pretend_run": args.pretend_run,
            "exit_on_failure": args.exit_on_failure
        }
        if args.action == config.SaveActionType.PACK:
            handler_kwargs["locker_type"] = args.locker_type
        success = handler(**handler_kwargs)
        if not success:
            logger.log_error(
                message = error_message,
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                game_name = game_info.get_name(),
                quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
