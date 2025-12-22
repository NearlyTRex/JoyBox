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
parser = arguments.ArgumentParser(description = "Nintendo DS rom tool.")
parser.add_input_path_argument()
parser.add_boolean_argument(args = ("-d", "--decrypt"), description = "Decrypt NDS files")
parser.add_boolean_argument(args = ("-e", "--encrypt"), description = "Verify NDS files")
parser.add_boolean_argument(args = ("-g", "--generate_hash"), description = "Output size and hashes to a companion file")
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
    action = "Decrypt" if args.decrypt else "Encrypt" if args.encrypt else None

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Action: %s" % action
        ]
        if not prompts.prompt_for_preview("NDS ROM tool", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Find rom files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".nds"]):
        current_file = file
        current_file_dir = paths.get_filename_directory(current_file)
        current_file_basename = paths.get_filename_basename(current_file)

        # Decrypt NDS file
        if args.decrypt:
            nintendo.DecryptNDSRom(
                nds_file = current_file,
                generate_hash = args.generate_hash,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Encrypt NDS file
        elif args.encrypt:
            nintendo.EncryptNDSRom(
                nds_file = current_file,
                generate_hash = args.generate_hash,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
