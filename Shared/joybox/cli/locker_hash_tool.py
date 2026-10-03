# Imports
import fnmatch
import os
import os.path
import sys
import joybox.config as config
import joybox.environment as environment
import joybox.paths as paths
import joybox.hashing as hashing
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.system as system
import joybox.logger as logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Record the XXH3 hash, size and modification time of every file in a locker directory.",
        details = (
            "Scans the locker directory, applies the hidden-file, include and exclude filters, and\n"
            "writes one CSV per group of files under `Locker/Hashes` in the configured file\n"
            "metadata directory (`file_metadata_dir` in `[UserData.Dirs]`). Files are grouped by\n"
            "the first `--depth` folders of their path relative to the locker: with the default\n"
            "depth of 2, `Documents/Taxes/2024/return.pdf` is recorded in `Documents/Taxes.csv`.\n"
            "Each row holds the file's directory, name, XXH3 hash, size and modification time.\n"
            "\n"
            "Existing CSVs are updated in place: a file whose size and modification time match its\n"
            "row is not hashed again. Afterwards, rows for files that no longer exist are removed\n"
            "from every CSV the run touched."),
        examples = [
            ("Hash the default locker with the default filters", "locker_hash_tool"),
            ("Show which files would be hashed without writing anything", "locker_hash_tool -p -v"),
            ("Hash only documents and photos", "locker_hash_tool -i \"Documents/**,Photos/**\""),
            ("Hash everything, including hidden files and the default exclusions", "locker_hash_tool -e \"\" --include_hidden"),
            ("Hash a locker on an external drive, one CSV per top-level folder", "locker_hash_tool -l /media/user/External -d 1"),
        ],
        notes = [
            "Filters are `fnmatch` globs matched against the whole relative path, where `*` also matches `/`, so `Documents/*` covers every file below `Documents`.",
            "The include filter is applied before the exclude filter, so an exclude always wins.",
            "A file in fewer than `--depth` folders is recorded under the folders it has, so `Photos/b.jpg` goes to `Photos.csv`; files at the locker root go to `root.csv`.",
        ],
        see_also = ["rebuild_hash_sidecars", "master_backup"],
        section = "Backups & Lockers")
    parser.add_string_argument(
        args = ("-l", "--locker_base_directory"),
        default = "$HOME/Locker",
        description = "Locker directory to scan; environment variables and `~` are expanded")
    parser.add_string_argument(
        args = ("-i", "--include_filter"),
        default = None,
        description = "Comma-separated glob patterns relative to the locker; when given, only matching files are hashed (e.g. `Documents/**,Photos/**`)")
    parser.add_string_argument(
        args = ("-e", "--exclude_filter"),
        default = "Gaming/Roms/**,Gaming/DLC/**,Gaming/Updates/**,Testing/**",
        description = "Comma-separated glob patterns relative to the locker; matching files are skipped. Pass an empty string to exclude nothing")
    parser.add_boolean_argument(
        args = ("--include_hidden",),
        description = "Also hash files whose path has a component starting with `.`; they are skipped by default")
    parser.add_integer_argument(
        args = ("-d", "--depth"),
        default = 2,
        description = "Number of leading folders that name a file's CSV, e.g. 2 groups `Documents/Taxes/...` into `Documents/Taxes.csv`")
    parser.add_common_arguments()
    return parser

# Main
def main():

    # Parse arguments
    parser = build_parser()
    args, unknown = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Check depth
    if args.depth < 1:
        logger.log_error("Depth must be at least 1", quit_program = True)

    # Get base directory
    base_dir = paths.expand_path(args.locker_base_directory)
    if not paths.does_path_exist(base_dir):
        logger.log_error("Base directory does not exist: %s" % base_dir, quit_program = True)

    # Parse filter patterns
    include_patterns = [p.strip() for p in args.include_filter.split(",") if p.strip()] if args.include_filter else []
    exclude_patterns = [p.strip() for p in args.exclude_filter.split(",") if p.strip()] if args.exclude_filter else []

    # Log file paths
    logger.log_info("Source: %s" % base_dir)
    logger.log_info("FileMetadata: %s" % environment.get_file_locker_hashes_root_dir())
    if include_patterns:
        logger.log_info("Include patterns: %s" % include_patterns)
    if exclude_patterns:
        logger.log_info("Exclude patterns: %s" % exclude_patterns)

    # Build list of all files relative to source
    logger.log_info("Scanning files...")
    file_list = paths.build_file_list(base_dir, use_relative_paths = True)

    # Exclude hidden files by default
    if not args.include_hidden:
        file_list = [f for f in file_list if not any(part.startswith(".") for part in f.split(os.sep))]

    # Apply include filter if specified (file must match at least one pattern)
    if include_patterns:
        file_list = [f for f in file_list if any(fnmatch.fnmatch(f, p) for p in include_patterns)]

    # Apply exclude filter if specified (file must not match any pattern)
    if exclude_patterns:
        file_list = [f for f in file_list if not any(fnmatch.fnmatch(f, p) for p in exclude_patterns)]

    # Log found files
    logger.log_info("Found %d files" % len(file_list))

    # Group files by their hash file destination
    files_by_hash_file = {}
    for file_path in file_list:
        hash_file = environment.get_file_locker_hashes_file(file_path, depth = args.depth)
        files_by_hash_file.setdefault(hash_file, []).append(file_path)

    # Process each group
    hash_files_processed = []
    failed_hash_files = []
    for hash_file, files in files_by_hash_file.items():
        logger.log_info("Processing: %s (%d files)" % (hash_file, len(files)))

        # Hash files in this group
        success = hashing.hash_files(
            src = files,
            output_file = hash_file,
            base_path = base_dir,
            hash_format = config.HashFormatType.CSV,
            include_enc_fields = False,
            verbose = args.verbose,
            pretend_run = args.pretend_run)
        if not success:
            logger.log_error("  Failed to write: %s" % hash_file)
            failed_hash_files.append(hash_file)
            continue
        hash_files_processed.append(hash_file)
        logger.log_info("  Wrote: %s" % hash_file)

    # Clean missing entries from all processed hash files
    logger.log_info("Cleaning missing entries...")
    for hash_file in hash_files_processed:
        success = hashing.clean_missing_hash_entries(
            hash_file = hash_file,
            locker_root = base_dir,
            hash_format = config.HashFormatType.CSV,
            verbose = args.verbose,
            pretend_run = args.pretend_run)
        if not success:
            logger.log_error("Failed to clean: %s" % hash_file)
            failed_hash_files.append(hash_file)
    if failed_hash_files:
        logger.log_error("%d hash files could not be written" % len(failed_hash_files))
        sys.exit(1)
    logger.log_info("Done!")

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
