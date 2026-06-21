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
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Clean hash files.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Show preview
    if not args.no_preview:
        details = [environment.get_game_hashes_metadata_root_dir()]
        if not prompts.prompt_for_preview("Clean game hash files (sort entries)", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Sort hash files
    success = collection.sort_all_hash_files(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        logger.log_error("Sort of hash file failed!", quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
