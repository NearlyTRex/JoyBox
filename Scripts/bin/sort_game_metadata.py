#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import metadata
import system
import arguments
import setup
import logger
import paths
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Sort game metadata entries.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get metadata dir
    metadata_dir = environment.get_game_pegasus_metadata_root_dir()

    # Find all metadata files
    metadata_files = []
    for filename in paths.build_file_list(metadata_dir):
        if environment.is_game_metadata_file(filename):
            metadata_files.append(filename)

    # Show preview
    if not args.no_preview:
        details = [
            "Metadata dir: %s" % metadata_dir,
            "Files to sort: %d" % len(metadata_files)
        ]
        if not prompts.prompt_for_preview("Sort game metadata", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Sort each metadata file
    files_sorted = 0
    for metadata_file in sorted(metadata_files):
        logger.log_info("Sorting: %s" % metadata_file)
        if not args.pretend_run:

            # Import metadata
            metadata_obj = metadata.Metadata()
            metadata_obj.import_from_metadata_file(metadata_file)

            # Export back
            metadata_obj.export_to_metadata_file(
                metadata_file = metadata_file,
                append_existing = False,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = False)
        files_sorted += 1

    # Report results
    logger.log_header("Sort complete: %d files sorted" % files_sorted)

# Start
if __name__ == "__main__":
    system.run_main(main)
