#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.environment as environment
import joybox.system as system
import joybox.gameinfo as gameinfo
import joybox.collection as collection
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts
import joybox.paths as paths

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Create or update the JSON file of each game found in a locker.",
    details = (
        "Lists the game folders in the locker for the selected categories and, for each one,\n"
        "creates its JSON file in the game metadata repository if missing, then fills it from\n"
        "the game's files: the file list (with real names when the locker is encrypted), the\n"
        "DLC, update, extra and dependency files kept in those subfolders, the most likely\n"
        "launch or transform file, and for store games the store's latest app data.\n"
        "\n"
        "JSON files live under `Json/<supercategory>/<category>/<subcategory>/` in the metadata\n"
        "repository, with an extra first-letter folder on platforms that use one. Values that\n"
        "are filled once are kept when already present, so re-running updates rather than\n"
        "replaces a file. Only the `Roms`, `DLC` and `Updates` supercategories have JSON files.\n"
        "\n"
        "The game directory is `-i` if given, otherwise the game's place under `-b`, otherwise\n"
        "the gaming folder of the `-l` locker (the Local locker when `-l` is omitted)."),
    examples = [
        ("Build JSON for one new update from the local locker", "build_game_json_files -u Updates -c Nintendo -s \"Nintendo Switch\" -n \"Pokemon Legends Z-A (World)\" -l Local"),
        ("Build JSON for a whole platform from a remote locker", "build_game_json_files -c Nintendo -s \"Nintendo Switch\" -l Hetzner"),
        ("Build JSON for all DLC", "build_game_json_files -u DLC -l Local"),
        ("Build one game's JSON from files in another directory", "build_game_json_files -i /path/to/game/files -c Nintendo -s \"Nintendo Switch\" -n \"Game Name\" -l Local"),
        ("Show what would be built without writing", "build_game_json_files -c Nintendo -s \"Nintendo Switch\" -l Local -p -v"),
    ],
    notes = [
        "Run this for a game newly added to a locker when `upload_game_files` reports that it cannot find the game's JSON file.",
        "`-n` must name a game folder that exists in the locker; games are always listed from the locker, even with `-i`.",
        "`-i` is used as the directory of every selected game, so use it together with `-n`.",
        "The supercategory defaults to `Roms`; pass `-u` for DLC or updates.",
    ],
    see_also = ["upload_game_files", "clean_game_json_files", "analyze_game_json_files", "build_game_metadata_files", "build_game_hash_files"],
    section = "Game Collection")
parser.add_group("Input")
parser.add_input_path_argument(description = "Directory holding the game's files, used instead of the locker directory")
parser.add_group("Selection")
parser.add_game_supercategory_argument(description = "Supercategory of the games to build")
parser.add_game_category_argument(description = "Category of the games to build; all categories when omitted")
parser.add_game_subcategory_argument(description = "Subcategory (platform) of the games to build; every subcategory of the selected categories when omitted")
parser.add_game_name_argument(description = "Build only the game with this exact folder name; every game in the locker when omitted")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    description = "Locker to list games from and read their files in; Local when omitted")
parser.add_enum_argument(
    args = ("-m", "--generation_mode"),
    arg_type = config.GenerationModeType,
    default = config.GenerationModeType.STANDARD,
    description = "How categories are selected: `Standard` walks the selected categories, `Custom` takes exactly the given category and subcategory")
parser.add_string_argument(
    args = ("-b", "--locker_base_dir"),
    default = None,
    description = "Locker root to list and read games from instead of the `-l` locker's mount path (its Gaming folder is used)")
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
    for game_supercategory, game_category, game_subcategory in gameinfo.iterate_selected_game_categories(
        parser = parser,
        generation_mode = args.generation_mode):
        game_names = gameinfo.find_locker_game_names(
            game_supercategory,
            game_category,
            game_subcategory,
            args.locker_type,
            locker_base_dir)
        if args.game_name:
            game_names = [g for g in game_names if g == args.game_name]
        for game_name in game_names:
            if parser.get_input_path(check_exists = False):
                game_root = parser.get_input_path(check_exists = False)
            elif locker_base_dir:
                game_offset = environment.get_locker_gaming_files_offset(
                    game_supercategory,
                    game_category,
                    game_subcategory,
                    game_name)
                game_root = paths.join_paths(locker_base_dir, config.LockerFolderType.GAMING, game_offset)
            else:
                game_root = None
            json_file = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name)
            games_to_process.append((game_supercategory, game_category, game_subcategory, game_name, game_root, json_file))

    # Show preview
    if not args.no_preview:
        details = [json_file for _, _, _, _, _, json_file in games_to_process]
        if not prompts.prompt_for_preview("Build game JSON files (source: %s)" % args.locker_type, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Build json files
    for game_supercategory, game_category, game_subcategory, game_name, game_root, _ in games_to_process:
        success = collection.build_game_json_file(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            game_root = game_root,
            locker_type = args.locker_type,
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
