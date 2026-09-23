#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.environment as environment
import joybox.gameinfo as gameinfo
import joybox.system as system
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger

# Parse arguments
parser = arguments.ArgumentParser(
    description = "List games whose JSON file has no files, or whose metadata marks them unplayable.",
    details = (
        "Goes through every game JSON file in the metadata repository, across all supercategories,\n"
        "categories and subcategories, and logs two lists: games whose JSON file lists no\n"
        "files, and games whose metadata entry does not have `playable` set to Yes.\n"
        "\n"
        "Nothing is changed; the lists are only written to the log."),
    examples = [
        ("Show both lists", "analyze_game_json_files"),
        ("Show only games with no files", "analyze_game_json_files -m MissingGameFiles"),
        ("Show only unplayable games", "analyze_game_json_files -m UnplayableGames"),
    ],
    see_also = ["build_game_json_files", "clean_game_json_files", "find_missing_game_metadata"],
    section = "Game Collection")
parser.add_enum_argument(
    args = ("-m", "--mode"),
    arg_type = config.AnalyzeModeType,
    default = config.AnalyzeModeType.ALL,
    description = "Which list to show: games with no files, unplayable games, or both")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Json lists
    json_files_no_files = []
    json_files_unplayable = []

    # Analyze json files
    for game_supercategory in config.Supercategory.members():
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)
                game_names = gameinfo.find_json_game_names(
                    game_supercategory,
                    game_category,
                    game_subcategory)
                for game_name in game_names:

                    # Get game info
                    game_info = gameinfo.GameInfo(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        verbose = args.verbose,
                        pretend_run = args.pretend_run,
                        exit_on_failure = args.exit_on_failure)
                    game_files = game_info.get_files()

                    # No files
                    if isinstance(game_files, list) and len(game_files) == 0:
                        json_files_no_files.append(json_file)

                    # Unplayable
                    if game_info.is_playable() == False:
                        json_files_unplayable.append(json_file)

    # List games with no files
    if args.mode == config.AnalyzeModeType.ALL or args.mode == config.AnalyzeModeType.MISSING_GAME_FILES:
        if len(json_files_no_files):
            logger.log_info("Games with no files:")
            for json_file in json_files_no_files:
                logger.log_info(json_file)

    # List unplayable games
    if args.mode == config.AnalyzeModeType.ALL or args.mode == config.AnalyzeModeType.UNPLAYABLE_GAMES:
        if len(json_files_unplayable):
            logger.log_info("Games marked as unplayable:")
            for json_file in json_files_unplayable:
                logger.log_info(json_file)

# Start
if __name__ == "__main__":
    system.run_main(main)
