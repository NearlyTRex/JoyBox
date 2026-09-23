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

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Add each game with a JSON file to its platform's Pegasus metadata file and fill in missing details.",
    details = (
        "For each selected game that has a JSON file, makes sure the subcategory's metadata file\n"
        "(`Pegasus/Roms/<category>/<subcategory>/metadata.pegasus.txt` in the metadata\n"
        "repository) has an entry for it. A new entry records the platform, categories and JSON\n"
        "file path, with `players` 1, `coop` No and `playable` Yes.\n"
        "\n"
        "If the entry is then missing any downloadable field (description, genre, coop,\n"
        "developer, publisher, players, release), the latest metadata is fetched and merged in:\n"
        "from the store for store platforms, and from GameFAQs otherwise. Entries that already\n"
        "have every downloadable field are left alone.\n"
        "\n"
        "Only the `Roms` supercategory has metadata files; other supercategories are skipped."),
    examples = [
        ("Build metadata for one game", "build_game_metadata_files -c Nintendo -s \"Nintendo Switch\" -n \"Pokemon Legends Z-A (World)\""),
        ("Build metadata for a whole platform", "build_game_metadata_files -c Sony -s \"Sony PlayStation 2\""),
        ("Build metadata for every game", "build_game_metadata_files"),
        ("Show what would be built", "build_game_metadata_files -c Computer -s Steam -p -v"),
    ],
    notes = [
        "Only games that already have a JSON file are processed; create it first with `build_game_json_files` or `build_game_store_purchases`.",
        "An existing entry is never recreated, only filled in.",
    ],
    see_also = ["build_game_json_files", "build_game_store_purchases", "find_missing_game_metadata", "download_game_metadata_assets", "sort_game_metadata", "publish_game_metadata_files"],
    section = "Game Collection")
parser.add_game_supercategory_argument(description = "Supercategory of the games; only `Roms` produces metadata")
parser.add_game_category_argument(description = "Category of the games to build; all categories when omitted")
parser.add_game_subcategory_argument(description = "Subcategory (platform) of the games to build; every subcategory of the selected categories when omitted")
parser.add_game_name_argument(description = "Build only the game with this exact name; every game with a JSON file when omitted")
parser.add_enum_argument(
    args = ("-m", "--generation_mode"),
    arg_type = config.GenerationModeType,
    default = config.GenerationModeType.STANDARD,
    description = "How categories are selected: `Standard` walks the selected categories, `Custom` takes exactly the given category and subcategory")
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
    for game_supercategory, game_category, game_subcategory in gameinfo.iterate_selected_game_categories(
        parser = parser,
        generation_mode = args.generation_mode):
        game_names = gameinfo.find_json_game_names(
            game_supercategory,
            game_category,
            game_subcategory)
        if args.game_name:
            game_names = [g for g in game_names if g == args.game_name]
        for game_name in game_names:
            metadata_file = environment.get_game_metadata_file(game_category, game_subcategory)
            games_to_process.append((game_supercategory, game_category, game_subcategory, game_name, metadata_file))

    # Show preview
    if not args.no_preview:
        details = list(set([metadata_file for _, _, _, _, metadata_file in games_to_process]))
        if not prompts.prompt_for_preview("Build game metadata files", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Build metadata files
    for game_supercategory, game_category, game_subcategory, game_name, _ in games_to_process:
        success = collection.build_game_metadata_entry(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error(
                message = "Build of metadata file failed!",
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                game_name = game_name,
                quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
