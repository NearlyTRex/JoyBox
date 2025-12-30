#!/usr/bin/env python3

# Imports
import os
import os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import gameinfo
import paths
import fileops
import hashing
import arguments
import setup
import system
import logger

# Parse arguments
parser = arguments.ArgumentParser(description = "Hash files from a locker directory.")
parser.add_string_argument(
    args = ("-s", "--source_path"),
    default = "/media/aryie/Locker",
    description = "Source path to locker root directory")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get source path
    source_path = args.source_path
    if not paths.does_path_exist(source_path):
        logger.log_error("Source path does not exist: %s" % source_path)
        return

    # Log file paths
    logger.log_info("Source: %s" % source_path)
    logger.log_info("FileMetadata: %s" % environment.get_file_locker_hashes_root_dir())
    logger.log_info("GameMetadata: %s" % environment.get_game_hashes_metadata_root_dir())

    # Build list of all files relative to source
    logger.log_info("Scanning files...")
    file_list = paths.build_file_list(source_path, use_relative_paths = True)
    logger.log_info("Found %d files" % len(file_list))

    # Group files by their hash file destination (first 4 path levels)
    files_by_hash_file = paths.group_files_by_path_depth(file_list, depth = 4)

    # Process each group
    for group_key, files in files_by_hash_file.items():
        logger.log_info("Processing: %s (%d files)" % (group_key, len(files)))

        # Determine hash file paths
        file_hash_file = environment.get_file_locker_hashes_file(group_key)

        # Check if this is a game path and get categories
        full_group_path = paths.join_paths(source_path, group_key)
        game_supercategory, game_category, game_subcategory = gameinfo.derive_game_categories_from_file(full_group_path)
        is_game_path = game_supercategory is not None

        # Get game hash file if applicable
        game_hash_file = None
        if is_game_path:
            game_hash_file = environment.get_game_hashes_metadata_file(
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory)

        # Load existing file hashes
        file_hash_contents = {}
        if paths.is_path_file(file_hash_file):
            file_hash_contents = hashing.read_hash_file_csv(
                src = file_hash_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run)

        # Load existing game hashes
        game_hash_contents = {}
        if game_hash_file and paths.is_path_file(game_hash_file):
            game_hash_contents = hashing.normalize_hash_contents(
                hashing.read_hash_file_json(
                    src = game_hash_file,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run))

        # Track files seen in this batch
        seen_files = set()

        # Process each file
        for file_path in files:
            seen_files.add(file_path)

            # Check if file needs to be hashed (based on mtime/size)
            needs_hash = args.pretend_run or hashing.does_file_need_to_be_hashed(
                src = file_path,
                base_path = source_path,
                hash_contents = file_hash_contents)
            if not needs_hash:
                if args.verbose:
                    logger.log_info("  Skipping (unchanged): %s" % file_path)
                continue

            # Log progress
            if args.pretend_run:
                if args.verbose:
                    logger.log_info("  [pretend] Would hash: %s" % file_path)
                else:
                    logger.log_progress_dot()
            elif args.verbose:
                logger.log_info("  Hashing: %s" % file_path)
            else:
                logger.log_progress_dot()

            # Calculate hash
            hash_data = hashing.calculate_hash_simple(
                src = file_path,
                base_path = source_path,
                verbose = False,
                pretend_run = args.pretend_run)

            # Write metadata
            if hash_data:
                file_hash_contents[file_path] = hash_data
                if is_game_path:
                    game_hash_contents[file_path] = hashing.convert_to_full_hash_entry(hash_data)

        # Remove entries for files that no longer exist
        keys_to_remove = [key for key in file_hash_contents.keys() if key not in seen_files]
        for key in keys_to_remove:
            if args.verbose:
                logger.log_info("  Removing (missing): %s" % key)
            del file_hash_contents[key]
            if key in game_hash_contents:
                del game_hash_contents[key]

        # Write file metadata
        if not args.pretend_run and file_hash_contents:
            fileops.make_directory(
                src = paths.get_filename_directory(file_hash_file),
                verbose = args.verbose,
                pretend_run = args.pretend_run)
            hashing.write_hash_file_csv(
                src = file_hash_file,
                hash_contents = file_hash_contents,
                verbose = args.verbose,
                pretend_run = args.pretend_run)
            logger.log_info("  Wrote: %s" % file_hash_file)

        # Write game metadata
        if not args.pretend_run and game_hash_contents:
            fileops.make_directory(
                src = paths.get_filename_directory(game_hash_file),
                verbose = args.verbose,
                pretend_run = args.pretend_run)
            hashing.write_hash_file_json(
                src = game_hash_file,
                hash_contents = game_hash_contents,
                verbose = args.verbose,
                pretend_run = args.pretend_run)
            logger.log_info("  Wrote: %s" % game_hash_file)
        logger.log_progress_newline()
    logger.log_info("Done!")

# Entry point
if __name__ == "__main__":
    system.run_main(main)
