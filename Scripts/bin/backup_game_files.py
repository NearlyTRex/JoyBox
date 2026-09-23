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

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Download store purchases whose build has changed and upload them, encrypted, to a locker.",
    details = (
        "Selects games from the game JSON metadata, not from the locker. For each game on a\n"
        "store platform that supports downloading purchases (Amazon Games, Epic Games, GOG,\n"
        "Humble Bundle, Itchio, Legacy Games, Steam), it asks the store for the latest build.\n"
        "When that differs from the build recorded in the game's JSON, it downloads the\n"
        "purchase to a temporary directory and hands it to the same encrypt, hash and upload\n"
        "steps as `upload_game_files`.\n"
        "\n"
        "Games on other platforms are skipped without doing anything.\n"
        "\n"
        "In `Standard` mode the games are those in the JSON metadata, narrowed by `-u`, `-c`,\n"
        "`-s` and `-n` (an exact game name). In `Custom` mode `-c`, `-s` and `-n` are required\n"
        "and name exactly one game."),
    examples = [
        ("Back up every changed Steam purchase to Hetzner", "backup_game_files -c Computer -s Steam -l Hetzner"),
        ("Preview a backup without downloading or uploading anything", "backup_game_files -c Computer -s GOG -l Hetzner -p -v"),
        ("Back up one GOG game", "backup_game_files -c Computer -s GOG -n \"Game Name\" -l Hetzner"),
    ],
    notes = [
        "Only `Computer` store subcategories do anything; the tool checks every selected game against its store, which can take a while without `-c` and `-s`.",
        "The first game that fails stops the run.",
    ],
    see_also = ["upload_game_files", "backup_tool"],
    section = "Backups & Lockers")
parser.add_group("Game selection")
parser.add_game_supercategory_argument(description = "Supercategory of the games to back up")
parser.add_game_category_argument(description = "Category of the games to back up; all categories when omitted in `Standard` mode")
parser.add_game_subcategory_argument(description = "Subcategory (platform or store) of the games to back up; all of the category's subcategories when omitted in `Standard` mode")
parser.add_game_name_argument(description = "Exact name of the game to back up; every game found when omitted in `Standard` mode")
parser.add_enum_argument(
    args = ("-m", "--generation_mode"),
    arg_type = config.GenerationModeType,
    default = config.GenerationModeType.STANDARD,
    description = "`Standard` finds games in the JSON metadata; `Custom` takes exactly the game named by `-c`, `-s` and `-n`")
parser.add_group("Output")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    description = "Locker to upload to; its passphrase encrypts the files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Collect games to process
    games_to_process = []
    for game_info in gameinfo.iterate_selected_game_infos(
        parser = parser,
        generation_mode = args.generation_mode,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure):
        games_to_process.append(game_info)

    # Show preview
    if not args.no_preview:
        details = [game_info.get_name() for game_info in games_to_process]
        if not prompts.prompt_for_preview("Backup game files (store -> %s)" % args.locker_type, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Backup game files
    for game_info in games_to_process:
        success = collection.backup_game_files(
            game_info = game_info,
            locker_type = args.locker_type,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error(
                message = "Backup of game files failed!",
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                game_name = game_info.get_name(),
                quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
