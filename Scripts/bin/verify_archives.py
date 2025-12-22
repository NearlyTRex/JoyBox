#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import archive
import arguments
import setup
import logger
import paths
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Verify archive files.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-a", "--archive_types"),
    arg_type = config.ArchiveFileType,
    default = [config.ArchiveFileType.ZIP],
    description = "Archive types",
    allow_multiple = True)
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Archive types: %s" % [t.cval() for t in args.archive_types]
        ]
        if not prompts.prompt_for_preview("Verify archives", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Verify archives
    archive_extensions = [archive_type.cval() for archive_type in args.archive_types]
    for file in paths.build_file_list_by_extensions(input_path, extensions = archive_extensions):
        logger.log_info("Verifying %s ..." % file)
        verification_success = archive.TestArchive(
            archive_file = file,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if verification_success:
            logger.log_info("Verified!")
        else:
            logger.log_error("Verification failed!", quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
