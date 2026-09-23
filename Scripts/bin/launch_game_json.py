#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import random

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.environment as environment
import joybox.platforms as platforms
import joybox.collection as collection
import joybox.metadata as metadata
import joybox.gameinfo as gameinfo
import joybox.arguments as arguments
import joybox.gui as gui
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths

# Setup argument parser
parser = arguments.ArgumentParser(
    description = "Launch a game described by its JSON file, installing it and restoring its save first.",
    details = (
        "The game is given as a JSON file with `-i`, or by `-c`, `-s` and `-n`, which name the\n"
        "JSON file under the `Roms` supercategory of the metadata repository; the `launch:` lines\n"
        "in the Pegasus metadata files use this second form. With `-r`, whatever is not given\n"
        "is picked at random, ending with a random game from that subcategory's metadata file.\n"
        "\n"
        "Games whose metadata does not mark them playable are refused. A store game is\n"
        "installed and started through its store, with its save imported before and exported\n"
        "after. Any other game is installed into the local cache if needed, its save is imported\n"
        "and linked into the emulator's save folder, the emulator's config file has its path\n"
        "placeholders filled in, and the emulator is run; afterwards the config is restored and\n"
        "the save exported.\n"
        "\n"
        "Errors are shown as a popup and end the run."),
    examples = [
        ("Launch a game by name", "launch_game_json -c Nintendo -s \"Nintendo 64\" -n \"Game Name (USA)\""),
        ("Launch a game from its JSON file, fullscreen", "launch_game_json -i \"/path/to/Game Name (USA).json\" -f"),
        ("Launch a random Nintendo game", "launch_game_json -c Nintendo -r"),
        ("Launch and record a video of the session", "launch_game_json -c Nintendo -s \"Nintendo 64\" -n \"Game Name (USA)\" -t Video"),
        ("Dry run", "launch_game_json -c Nintendo -s \"Nintendo 64\" -n \"Game Name (USA)\" -p -v"),
    ],
    notes = [
        "Capture length, interval, area and frame rate come from the `[UserData.Capture]` section of JoyBox.ini.",
        "Random selection skips subcategories whose platform has no launcher.",
    ],
    see_also = ["install_game_json", "launch_pegasus", "save_game_tool"],
    section = "Game Launching")
parser.add_group("Game")
parser.add_input_path_argument(description = "Game JSON file to launch; takes priority over `-c`, `-s` and `-n`")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    default = config.LockerType.HETZNER,
    description = "Locker type passed to the install step")
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

# Parse arguments
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Json file to load
    json_file = None

    # Prefer input file if it was specified
    if args.input_path:
        json_file = parser.get_input_path()

    # Next use category values
    elif args.game_category and args.game_subcategory and args.game_name:
        json_file = environment.get_game_json_metadata_file(
            game_supercategory = config.Supercategory.ROMS,
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            game_name = args.game_name)

    # Finally, use random selection
    elif args.fill_with_random:

        # Get category
        game_category = args.game_category
        if not game_category:
            game_category = random.choice(config.Category.members())

        # Get subcategory
        game_subcategory = args.game_subcategory
        if not game_subcategory:
            potential_subcategories = []
            for potential_subcategory in config.subcategory_map[game_category]:
                potential_platform = gameinfo.derive_game_platform_from_categories(game_category, potential_subcategory)
                if not platforms.has_no_launcher(potential_platform):
                    potential_subcategories.append(potential_subcategory)
            game_subcategory = random.choice(potential_subcategories)

        # Read metadata for this category/subcategory pair
        metadata_file = environment.get_game_metadata_file(game_category, game_subcategory)
        metadata_obj = metadata.Metadata()
        metadata_obj.import_from_metadata_file(metadata_file)

        # Select random game entry
        random_game_entry = metadata_obj.get_random_entry()

        # Get json file
        if random_game_entry:
            json_file = environment.get_game_json_metadata_file(
                game_supercategory = config.Supercategory.ROMS,
                game_category = random_game_entry[config.metadata_key_category],
                game_subcategory = random_game_entry[config.metadata_key_subcategory],
                game_name = random_game_entry[config.metadata_key_game])

    # Check json file
    if not json_file:
        gui.display_error_popup(
            title_text = "No json file specified",
            message_text = "No json file was specified")
    if not paths.is_path_file(json_file):
        gui.display_error_popup(
            title_text = "Json file not found",
            message_text = "Json file %s was not found" % json_file)

    # Get game info
    game_info = gameinfo.GameInfo(
        json_file = json_file,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

    # Check ability to launch
    if not game_info.is_playable():
        gui.display_error_popup(
            title_text = "Json file not launchable",
            message_text = "Json file '%s' is not launchable" % paths.get_filename_file(json_file))

    # Launch game
    success = collection.launch_game(
        game_info = game_info,
        locker_type = args.locker_type,
        capture_type = args.capture_type,
        fullscreen = args.fullscreen,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        gui.display_error_popup(
            title_text = "Json file failed to launch",
            message_text = "Json file '%s' failed to launch" % paths.get_filename_file(json_file))

# Start
if __name__ == "__main__":
    system.run_main(main)
