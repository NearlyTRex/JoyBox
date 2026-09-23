#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.environment as environment
import joybox.collection as collection
import joybox.gameinfo as gameinfo
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts
import joybox.paths as paths

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Record hashes of each selected game's files in the per-subcategory hash file.",
    details = (
        "For each selected game, hashes every file under the game's directory and merges the\n"
        "records into the subcategory's hash file in the game metadata repository\n"
        "(`Hashes/<supercategory>/<category>/<subcategory>.json`). Files whose entries are\n"
        "unchanged are skipped, so re-running only hashes what is new or modified.\n"
        "\n"
        "The game directory is taken from `-i` if given, otherwise from the game's place under\n"
        "`-b`, otherwise from the gaming folder of the `-l` locker (the Local locker when `-l`\n"
        "is omitted). Records include the encrypted name, hash and size computed with that\n"
        "locker's passphrase, so they match what an encrypted remote locker holds.\n"
        "\n"
        "Games are listed from the locker when `-l` or `-b` is given, and from the JSON files\n"
        "in the metadata repository otherwise. With `-d`, entries for files that no longer\n"
        "exist under the locker's gaming folder are removed afterwards, once per subcategory."),
    examples = [
        ("Hash a platform from the local locker", "build_game_hash_files -c Nintendo -s \"Nintendo Switch\" -l Local"),
        ("Hash and drop entries for deleted files", "build_game_hash_files -c Nintendo -s \"Nintendo Switch\" -l Local -d"),
        ("Hash from a locker copy mounted elsewhere", "build_game_hash_files -c Nintendo -s \"Nintendo Switch\" -b /mnt/backup/locker"),
        ("Show what would be hashed without writing", "build_game_hash_files -c Sony -s \"Sony PlayStation 2\" -l Local -p -v"),
    ],
    notes = [
        "Choose the `-l` locker that matches the content being hashed; its passphrase determines the encrypted fields.",
        "`-i` is used as the directory of every selected game.",
        "The supercategory defaults to `Roms`; pass `-u` to hash DLC or updates.",
    ],
    see_also = ["clean_game_hash_files", "verify_game_files", "build_game_json_files"],
    section = "Game Collection")
parser.add_group("Input")
parser.add_input_path_argument(description = "Directory to hash instead of the game's locker directory")
parser.add_group("Selection")
parser.add_game_supercategory_argument(description = "Supercategory of the games to hash")
parser.add_game_category_argument(description = "Category of the games to hash; all categories when omitted")
parser.add_game_subcategory_argument(description = "Subcategory (platform) of the games to hash; every subcategory of the selected categories when omitted")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    description = "Locker whose gaming folder holds the files and whose passphrase is used for the encrypted fields; Local when omitted. When given, games are listed from this locker")
parser.add_enum_argument(
    args = ("-m", "--generation_mode"),
    arg_type = config.GenerationModeType,
    default = config.GenerationModeType.STANDARD,
    description = "How games are selected: `Standard` walks the selected categories, `Custom` takes exactly the given category and subcategory")
parser.add_string_argument(
    args = ("-b", "--locker_base_dir"),
    default = None,
    description = "Locker root to list and read games from instead of the `-l` locker's mount path (its Gaming folder is used)")
parser.add_group("Behavior")
parser.add_boolean_argument(
    args = ("-d", "--delete_missing"),
    description = "After hashing, remove entries for files that no longer exist in the locker")
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
