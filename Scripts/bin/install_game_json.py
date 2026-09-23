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
import joybox.gui as gui
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Install a game described by its JSON file into the local game cache.",
    details = (
        "The game is given either as a JSON file with `-i`, or by `-c`, `-s` and `-n`, which\n"
        "name the JSON file under the `Roms` supercategory of the metadata repository.\n"
        "\n"
        "A store game is installed with that store's own installer. Any other game is copied\n"
        "from its remote ROM folder, decrypted, into its local cache folder, and first\n"
        "transformed when its platform needs that (computer games, for example, are set up from\n"
        "their installer files). A game that is already in the cache is left as it is.\n"
        "\n"
        "With `-a`, the game's DLC and updates are then installed into the emulators that\n"
        "handle its platform. Errors are shown as a popup and end the run."),
    examples = [
        ("Install a game from its JSON file", "install_game_json -i \"/path/to/Game Name (USA).json\""),
        ("Install a game with its DLC and updates", "install_game_json -i \"/path/to/Game Name (USA).json\" -a"),
        ("Install a computer game and keep its setup folder", "install_game_json -i \"/path/to/Game Name (USA).json\" -k"),
        ("Dry run", "install_game_json -i \"/path/to/Game Name (USA).json\" -p -v"),
    ],
    see_also = ["launch_game_json", "build_game_json_files"],
    section = "Game Launching")
parser.add_group("Game")
parser.add_input_path_argument(description = "Game JSON file to install; takes priority over `-c`, `-s` and `-n`")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    default = config.LockerType.HETZNER,
    description = "Source locker named in the preview")
parser.add_game_category_argument(description = "Category of the game, used with `-s` and `-n` to find its JSON file")
parser.add_game_subcategory_argument(description = "Subcategory (platform) of the game, used with `-c` and `-n` to find its JSON file")
parser.add_game_name_argument(description = "Name of the game, used with `-c` and `-s` to find its JSON file")
parser.add_group("Behavior")
parser.add_boolean_argument(args = ("-k", "--keep_setup_files"), description = "Keep the setup folder after a computer game is set up from its installer files")
parser.add_boolean_argument(args = ("-a", "--install_addon_files"), description = "Also install the game's DLC and updates into the emulators for its platform")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

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

    # Show preview
    if not args.no_preview:
        details = [
            "JSON file: %s" % json_file,
            "Game: %s" % game_info.get_name(),
            "Source: %s" % args.locker_type
        ]
        if not prompts.prompt_for_preview("Install game", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Install game
    success = collection.install_game(
        game_info = game_info,
        locker_type = args.locker_type,
        keep_setup_files = args.keep_setup_files,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        gui.display_error_popup(
            title_text = "Json file failed to install",
            message_text = "Json file '%s' failed to install" % paths.get_filename_file(json_file))

    # Install game addons
    if args.install_addon_files:
        success = collection.install_game_addons(
            game_info = game_info,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            gui.display_error_popup(
                title_text = "Json file addons failed to install",
                message_text = "Json file '%s' addons failed to install" % paths.get_filename_file(json_file))

# Start
if __name__ == "__main__":
    system.run_main(main)
