#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.arguments as arguments
import joybox.system as system
import joybox.setup as setup
import joybox.logger as logger

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Link the Pegasus frontend's asset folders to the artwork in the locker.",
    details = (
        "Walks every game category and subcategory and, for each asset type (box art,\n"
        "screenshots, backgrounds and so on), creates a symlink from the Pegasus metadata\n"
        "asset directory to the matching artwork directory in the locker. A locker artwork\n"
        "directory that does not exist yet is created first, so every link has a target.\n"
        "\n"
        "Run it after building game metadata, or whenever the asset directory layout changes.\n"
        "It takes only the common options."),
    examples = [
        ("Create all asset symlinks", "setup_game_assets -v"),
        ("Preview without making changes", "setup_game_assets -p -v"),
    ],
    notes = [
        "Symlinks must be supported on the system; the requirement check exits otherwise.",
        "Missing artwork directories are created, so the command is safe to re-run.",
        "It stops at the first symlink that cannot be created.",
    ],
    see_also = ["download_game_metadata_assets", "build_game_metadata_files", "setup_tools", "setup_game_emulators"],
    section = "Setup & Installation")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Setup assets
    setup.setup_assets(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
