#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import chd
import arguments
import setup
import logger
import paths
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Verify disc images from CHD files.")
parser.add_input_path_argument()
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    if not args.no_preview:
        details = ["Path: %s" % input_path]
        if not prompts.prompt_for_preview("Verify CHD", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Convert disc image files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".chd"]):

        # Verify disc chd
        logger.log_info("Verifying %s ..." % file)
        verification_success = chd.VerifyDiscCHD(file)
        if verification_success:
            logger.log_info("Verified!")
        else:
            logger.log_error("Verification failed!", quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
