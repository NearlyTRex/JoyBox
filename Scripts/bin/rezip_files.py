#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import archive
import arguments
import setup
import logger

# Parse arguments
parser = arguments.ArgumentParser(description = "Rezip files deterministically.")
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
        if not system.PromptForPreview("Rezip files deterministically", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Rezip zip files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".zip"]):
        current_file = file
        current_file_dir = system.GetFilenameDirectory(current_file)
        current_file_basename = system.GetFilenameBasename(current_file)
        current_file_extract_dir = system.JoinPaths(current_file_dir, current_file_basename + "_extracted")

        # Unzip file
        logger.log_info("Unzipping file %s ..." % current_file)
        success = archive.ExtractArchive(
            archive_file = current_file,
            extract_dir = current_file_extract_dir,
            delete_original = True,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error("Unable to unzip file %s" % current_file, quit_program = True)

        # Deterministically zip file
        logger.log_info("Deterministically rezipping ...")
        success = archive.CreateArchiveFromFolder(
            archive_file = current_file,
            source_dir = current_file_extract_dir,
            delete_original = True,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error("Unable to rezip file %s" % current_file, quit_program = True)

# Start
if __name__ == "__main__":
    system.RunMain(main)
