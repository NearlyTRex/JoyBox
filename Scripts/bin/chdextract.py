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
parser = arguments.ArgumentParser(description = "Extract disc images from CHD files.")
parser.add_input_path_argument()
parser.add_string_argument(args = ("-t", "--toc_ext"), default = ".cue", description = "Table of contents output extension")
parser.add_string_argument(args = ("-b", "--bin_ext"), default = ".bin", description = "Binary output extension")
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

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Output: %s + %s" % (args.toc_ext, args.bin_ext),
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("Extract CHD", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Convert disc image files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".chd"]):

        # Get file info
        current_file = file
        current_dir = paths.get_filename_directory(current_file)
        current_basename = paths.get_filename_basename(current_file)

        # Check if output already exists
        output_bin = paths.join_paths(current_dir, current_basename + args.bin_ext)
        output_toc = paths.join_paths(current_dir, current_basename + args.toc_ext)
        if os.path.exists(output_bin) or os.path.exists(output_toc):
            continue

        # Extract disc chd
        chd.ExtractDiscCHD(
            chd_file = current_file,
            binary_file = output_bin,
            toc_file = output_toc,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
