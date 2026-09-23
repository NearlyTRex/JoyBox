#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.arguments as arguments
import joybox.collection as collection
import joybox.gameinfo as gameinfo
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Archive, restore and back up game saves.",
    details = (
        "Works on each selected game that has a JSON entry. Two directories are involved: the\n"
        "live save directory in the cache (`Wine` or `Sandboxie` below it for `Computer` games,\n"
        "depending on the host), and the save archive directory in the local locker,\n"
        "`Gaming/Saves/<category>/<subcategory>/<game>`.\n"
        "\n"
        "Actions:\n"
        "\n"
        "- `Pack`: zip the live save directory, test the zip, and skip it if an identical\n"
        "  archive is already in the save archive directory. Otherwise copy it to that path,\n"
        "  as `<game>_<timestamp>.zip`, in each locker selected by `-l`.\n"
        "- `Unpack`: extract the newest archive from the save archive directory into the live\n"
        "  save directory.\n"
        "- `Export`: for store games, copy the save files from the store's save paths on this\n"
        "  machine (as recorded in the game's JSON entry) into a temporary tree and pack that.\n"
        "  For other games, the same as `Pack`.\n"
        "- `Import`: for non-store games, the same as `Unpack` when there is an archive to\n"
        "  unpack. For store games, nothing.\n"
        "- `ImportSavePaths`: for store games, list the files inside the save archives,\n"
        "  convert them to tokenized store paths, and merge them into the game's JSON entry.\n"
        "\n"
        "Games are selected with `-c`, `-s` and `-n`; any that is omitted matches everything,\n"
        "so with none of them the action runs over every game."),
    examples = [
        ("Capture the current saves of an installed Steam game", "save_game_tool -a Export -c Computer -s Steam -n \"Hades (World)\" -l Local"),
        ("Preview exporting every store game's saves", "save_game_tool -a Export -c Computer -p -v"),
        ("Pack a Switch game's saves into every configured locker", "save_game_tool -a Pack -c Nintendo -s \"Nintendo Switch\" -n \"Game Name\""),
        ("Restore the newest save archive into place", "save_game_tool -a Unpack -c Computer -s Steam -n \"Hades (World)\""),
        ("Record save paths for all Steam games from their archives", "save_game_tool -a ImportSavePaths -c Computer -s Steam"),
    ],
    notes = [
        "`Pack` archives what is already in the live save directory; to capture fresh saves from an installed store game use `Export`.",
        "Every pack or export writes a new timestamped archive rather than replacing an old one, unless an identical archive already exists.",
        "Archives are copied to the lockers as plain zip files, without encryption.",
        "The first game that fails stops the run.",
    ],
    see_also = ["backup_tool", "upload_game_files"],
    section = "Save Games")
parser.add_group("Action")
parser.add_input_path_argument(description = "Not used by any action")
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.SaveActionType,
    default = config.SaveActionType.PACK,
    description = "What to do with each selected game's saves; see the list above")
parser.add_group("Game selection")
parser.add_game_category_argument(description = "Category of the games to process; every category when omitted")
parser.add_game_subcategory_argument(description = "Subcategory (platform or store) of the games to process; every subcategory of the category when omitted")
parser.add_game_name_argument(description = "Exact name of the game to process; every game when omitted")
parser.add_group("Output")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    default = config.LockerType.ALL,
    description = "Locker to copy new archives to for `Pack` and `Export`; `All` means every configured locker")
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
        config.SaveActionType.PACK: (collection.pack_save, "Packing of save failed!"),
        config.SaveActionType.UNPACK: (collection.unpack_save, "Unpacking of save failed!"),
        config.SaveActionType.IMPORT: (collection.import_game_save, "Import of save failed!"),
        config.SaveActionType.EXPORT: (collection.export_game_save, "Export of save failed!"),
        config.SaveActionType.IMPORT_SAVE_PATHS: (collection.import_game_save_paths, "Import of save paths failed!"),
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
        if args.action in (config.SaveActionType.PACK, config.SaveActionType.EXPORT):
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
