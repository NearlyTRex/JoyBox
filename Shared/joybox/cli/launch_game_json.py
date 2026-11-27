# Imports
from joybox import config
from joybox import system
from joybox import collection
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "launch_game_json")
    parser.add_group("Game")
    parser.add_input_path_argument(description = "Game JSON file to launch; takes priority over `-c`, `-s` and `-n`")
    parser.add_enum_argument(
        args = ("-l", "--locker_type"),
        arg_type = config.LockerType,
        default = config.LockerType.HETZNER,
        description = "Locker the install step reads from, and where saves are backed up after the game exits (a local copy is always kept)")
    parser.add_game_category_argument(description = "Category of the game, used with `-s` and `-n` to find its JSON file")
    parser.add_game_subcategory_argument(description = "Subcategory (platform) of the game, used with `-c` and `-n` to find its JSON file")
    parser.add_game_name_argument(description = "Name of the game, used with `-c` and `-s` to find its JSON file")
    parser.add_boolean_argument(args = ("-r", "--fill_with_random"), description = "When `-i` or the full `-c`/`-s`/`-n` set is not given, pick the missing category, subcategory and game at random")
    parser.add_group("Behavior")
    parser.add_enum_argument(
        args = ("-t", "--capture_type"),
        arg_type = config.CaptureType,
        description = "Capture screenshots or a video while an emulated game runs; no capture when omitted")
    parser.add_boolean_argument(args = ("-f", "--fullscreen"), description = "Ask the emulator to run fullscreen")
    parser.add_common_arguments()
    return parser

# Launch the playable game named by a JSON file, by category and name, or picked at random, installing it and restoring its save first
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

    # Launch the game
    collection.launching.launch_game_from_json(
        json_file = json_file,
        game_category = args.game_category,
        game_subcategory = args.game_subcategory,
        game_name = args.game_name,
        fill_with_random = args.fill_with_random,
        locker_type = args.locker_type,
        capture_type = args.capture_type,
        fullscreen = args.fullscreen,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
