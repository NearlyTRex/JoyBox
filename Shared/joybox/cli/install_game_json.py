# Imports
from joybox import config
from joybox import system
from joybox import collection
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "install_game_json")
    parser.add_group("Game")
    parser.add_input_path_argument(description = "Game JSON file to install; takes priority over `-c`, `-s` and `-n`")
    parser.add_enum_argument(
        args = ("-l", "--locker_type"),
        arg_type = config.LockerType,
        default = config.LockerType.HETZNER,
        description = "Locker to install the game's files from")
    parser.add_game_category_argument(description = "Category of the game, used with `-s` and `-n` to find its JSON file")
    parser.add_game_subcategory_argument(description = "Subcategory (platform) of the game, used with `-c` and `-n` to find its JSON file")
    parser.add_game_name_argument(description = "Name of the game, used with `-c` and `-s` to find its JSON file")
    parser.add_group("Behavior")
    parser.add_boolean_argument(args = ("-k", "--keep_setup_files"), description = "Keep the setup folder after a computer game is set up from its installer files")
    parser.add_boolean_argument(args = ("-a", "--install_addon_files"), description = "Also install the game's DLC and updates into the emulators for its platform")
    parser.add_common_arguments()
    return parser

# After a preview, install the game named by a JSON file or by category, subcategory and name into the local cache, then its addons
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Prefer input file if it was specified
    json_file = None
    if args.input_path:
        json_file = parser.get_input_path()

    # Install the game, then its addons
    collection.installing.install_game_from_json(
        json_file = json_file,
        game_category = args.game_category,
        game_subcategory = args.game_subcategory,
        game_name = args.game_name,
        locker_type = args.locker_type,
        keep_setup_files = args.keep_setup_files,
        install_addon_files = args.install_addon_files,
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
