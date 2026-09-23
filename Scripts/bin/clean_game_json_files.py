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
import joybox.paths as paths
import joybox.prompts as prompts
import joybox.serialization as serialization

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Tidy every game JSON file: sort its keys and drop empty values.",
    details = (
        "Rewrites each game JSON file in the metadata repository, across all supercategories,\n"
        "categories and subcategories, with keys sorted and four-space indentation.\n"
        "\n"
        "Top-level keys whose value is null, an empty string, an empty list or object, or\n"
        "`false` are removed. Nested values are left as they are."),
    examples = [
        ("Clean every JSON file", "clean_game_json_files"),
        ("Clean without the confirmation prompt", "clean_game_json_files --no-preview"),
        ("Show which files would be cleaned", "clean_game_json_files -p -v"),
    ],
    notes = [
        "There are no selection options; every JSON file is processed.",
        "A key set to `false` is removed, so a false flag and a missing flag end up the same.",
    ],
    see_also = ["build_game_json_files", "analyze_game_json_files", "clean_game_hash_files", "clean_game_metadata_files"],
    section = "Game Collection")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Collect json files to process
    json_files_to_process = []
    for game_supercategory in config.Supercategory.members():
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)
                game_names = gameinfo.find_json_game_names(
                    game_supercategory,
                    game_category,
                    game_subcategory)
                for game_name in game_names:

                    # Get json file
                    json_file = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name)
                    if not paths.is_path_file(json_file):
                        continue
                    json_files_to_process.append(json_file)

    # Show preview
    if not args.no_preview:
        if not prompts.prompt_for_preview("Clean game JSON files (sort keys, remove empty values)", json_files_to_process):
            logger.log_warning("Operation cancelled by user")
            return

    # Clean json files
    for json_file in json_files_to_process:
        serialization.clean_json_file(
            src = json_file,
            sort_keys = True,
            remove_empty_values = True,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
