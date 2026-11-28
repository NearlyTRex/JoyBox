# Imports
from joybox import config
from joybox import system
from joybox import collection
from joybox import gamecollection
from joybox import arguments
from joybox import setup
from joybox import paths

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "build_game_hash_files")
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
    parser.add_generation_mode_argument(description = "How games are selected: `Standard` walks the selected categories, `Custom` takes exactly the given category and subcategory")
    parser.add_string_argument(
        args = ("-b", "--locker_base_dir"),
        default = None,
        description = "Locker root to list and read games from instead of the `-l` locker's mount path (its Gaming folder is used)")
    parser.add_group("Behavior")
    parser.add_boolean_argument(
        args = ("-d", "--delete_missing"),
        description = "After hashing, remove entries for files that no longer exist in the locker")
    parser.add_common_arguments()
    return parser

# After a preview, hash each selected game's files into its subcategory hash file, then drop entries whose files are gone
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get locker base dir
    locker_base_dir = paths.expand_path(args.locker_base_dir) if args.locker_base_dir else None

    # After a preview, hash each selected game, then clean missing hash entries
    collection.hashing.build_selected_hash_files(
        game_infos = gamecollection.iterate_selected_game_infos(
            parser = parser,
            generation_mode = args.generation_mode,
            locker_type = args.locker_type,
            locker_base_dir = locker_base_dir,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure),
        input_path = parser.get_input_path(check_exists = False),
        locker_type = args.locker_type,
        locker_base_dir = locker_base_dir,
        delete_missing = args.delete_missing,
        show_preview = not args.no_preview,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
