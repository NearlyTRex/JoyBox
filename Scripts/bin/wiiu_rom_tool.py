#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import nintendo
import arguments
import setup
import logger
import paths
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Nintendo Wii U rom tool.")
parser.add_input_path_argument()
parser.add_boolean_argument(args = ("-r", "--decrypt_nus"), description = "Decrypt NUS packages")
parser.add_boolean_argument(args = ("-e", "--verify_nus"), description = "Verify NUS packages")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete original files")
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

    # Determine action
    action = "Decrypt NUS" if args.decrypt_nus else "Verify NUS" if args.verify_nus else None

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Action: %s" % action
        ]
        if args.delete_originals:
            details.append("Delete originals: %s" % args.delete_originals)
        if not prompts.prompt_for_preview("Wii U ROM tool", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Find rom files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".tik"]):
        if file.endswith("title.tik"):
            current_file = file
            current_file_dir = paths.get_filename_directory(current_file)
            current_file_basename = paths.get_filename_basename(current_file)

            # Decrypt NUS package
            if args.decrypt_nus:
                nintendo.DecryptWiiUNUSPackage(
                    nus_package_dir = current_file_dir,
                    delete_original = args.delete_originals,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

            # Verify NUS package
            elif args.verify_nus:
                nintendo.VerifyWiiUNUSPackage(
                    nus_package_dir = current_file_dir,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
