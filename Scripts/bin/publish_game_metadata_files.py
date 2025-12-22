#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import collection
import arguments
import setup
import logger
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Publish metadata files.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Show preview
    if not args.no_preview:
        publish_dir = environment.GetGamePublishedMetadataRootDir()
        if not prompts.prompt_for_preview("Publish game metadata files to HTML", [publish_dir]):
            logger.log_warning("Operation cancelled by user")
            return

    # Publish game metadata files
    logger.log_info("Publishing game metadata files ...")
    success = collection.PublishAllGameMetadataEntries(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        logger.log_error("Publishing metadata files failed", quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
