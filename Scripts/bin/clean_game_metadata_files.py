#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import metadata
import environment
import arguments
import setup
import logger
import paths
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Clean metadata files.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Collect metadata files to process
    metadata_files_to_process = []
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:

            # Get metadata file
            metadata_file = environment.GetGameMetadataFile(game_category, game_subcategory)
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
    system.RunMain(main)
