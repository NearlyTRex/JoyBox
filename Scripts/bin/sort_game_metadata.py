#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.environment as environment
import joybox.metadata as metadata
import joybox.system as system
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Rewrite every Pegasus metadata file found under the metadata repository in sorted order.",
    details = (
        "Finds every `metadata.pegasus.txt` under the `Pegasus` folder of the game metadata\n"
        "repository, imports each one and exports it back to the same path. The rewrite sorts\n"
        "entries by name and regenerates the collection header and launch command, which keeps\n"
        "diffs small after bulk edits.\n"
        "\n"
        "`clean_game_metadata_files` does the same but only for the known category and\n"
        "subcategory paths; this tool also picks up files anywhere else under `Pegasus`."),
    examples = [
        ("Sort every metadata file", "sort_game_metadata"),
        ("List the files that would be sorted", "sort_game_metadata -p"),
        ("Sort without the confirmation prompt", "sort_game_metadata -v --no-preview"),
    ],
    notes = [
        "There are no selection options; every metadata file is processed.",
        "With `-p` the files are listed but not read or rewritten.",
    ],
    see_also = ["clean_game_metadata_files", "build_game_metadata_files", "publish_game_metadata_files"],
    section = "Game Collection")
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
