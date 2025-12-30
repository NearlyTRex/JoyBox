#!/usr/bin/env python3

# Imports
import os
import os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import paths
import hashing
import arguments
import setup
import system
import logger

# Parse arguments
parser = arguments.ArgumentParser(description = "Hash files from a locker directory.")
parser.add_string_argument(
    args = ("-l", "--locker_base_directory"),
    default = "/media/aryie/Locker",
    description = "Base directory of the locker")
parser.add_string_argument(
    args = ("-f", "--filter"),
    default = None,
    description = "Only process paths starting with this prefix (e.g., 'Documents')")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get base directory
    base_dir = args.locker_base_directory
    if not paths.does_path_exist(base_dir):
        logger.log_error("Base directory does not exist: %s" % base_dir)
        return

    # Log file paths
    logger.log_info("Source: %s" % base_dir)
    logger.log_info("FileMetadata: %s" % environment.get_file_locker_hashes_root_dir())
    if args.filter:
        logger.log_info("Filter: %s" % args.filter)

    # Build list of all files relative to source
    logger.log_info("Scanning files...")
    file_list = paths.build_file_list(base_dir, use_relative_paths = True)

    # Apply filter if specified
    if args.filter:
        file_list = [f for f in file_list if f.startswith(args.filter)]
    logger.log_info("Found %d files" % len(file_list))

    # Group files by their hash file destination (first 4 path levels)
    files_by_hash_file = paths.group_files_by_path_depth(file_list, depth = 4)

    # Process each group
    for group_key, files in files_by_hash_file.items():
        logger.log_info("Processing: %s (%d files)" % (group_key, len(files)))

        # Determine hash file path
        hash_file = environment.get_file_locker_hashes_file(group_key)

        # Hash files in this group
        hashing.hash_files(
            src = files,
            output_file = hash_file,
            base_path = base_dir,
            hash_format = config.HashFormatType.CSV,
            include_enc_fields = False,
            delete_missing = True,
            verbose = args.verbose,
            pretend_run = args.pretend_run)
        logger.log_info("  Wrote: %s" % hash_file)
    logger.log_info("Done!")

# Entry point
if __name__ == "__main__":
    system.run_main(main)
