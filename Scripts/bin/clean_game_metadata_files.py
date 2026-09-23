#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.metadata as metadata
import joybox.environment as environment
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Rewrite every platform's Pegasus metadata file with its entries in sorted order.",
    details = (
        "For each category and subcategory, reads the metadata file\n"
        "`Pegasus/Roms/<category>/<subcategory>/metadata.pegasus.txt` in the game metadata\n"
        "repository, if it exists, and writes it back with entries sorted by name and the\n"
        "collection header and launch command regenerated.\n"
        "\n"
        "`sort_game_metadata` does the same for every metadata file it finds under `Pegasus/`,\n"
        "including ones outside the known subcategories."),
    examples = [
        ("Sort every metadata file", "clean_game_metadata_files"),
        ("Sort without the confirmation prompt", "clean_game_metadata_files --no-preview"),
    ],
    notes = [
        "There are no selection options; every known subcategory is processed.",
    ],
    see_also = ["sort_game_metadata", "build_game_metadata_files", "clean_game_json_files", "clean_game_hash_files"],
    section = "Game Collection")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Collect metadata files to process
    metadata_files_to_process = []
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:

            # Get metadata file
            metadata_file = environment.get_game_metadata_file(game_category, game_subcategory)
            if not paths.is_path_file(metadata_file):
                continue
            metadata_files_to_process.append((game_category, game_subcategory, metadata_file))

    # Show preview
    if not args.no_preview:
        details = [metadata_file for _, _, metadata_file in metadata_files_to_process]
        if not prompts.prompt_for_preview("Clean game metadata files (sort entries)", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Sort metadata files
    for game_category, game_subcategory, metadata_file in metadata_files_to_process:
        logger.log_info("Sorting metadata files for %s - %s..." % (game_category, game_subcategory))
        metadata_obj = metadata.Metadata()
        metadata_obj.import_from_metadata_file(metadata_file)
        metadata_obj.export_to_metadata_file(metadata_file)

# Start
if __name__ == "__main__":
    system.run_main(main)
