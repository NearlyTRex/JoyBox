# Imports
import sys
from joybox import hashing
from joybox import arguments
from joybox import setup
from joybox import system

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "locker_hash_tool")
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

# Write the XXH3 hash, size and mtime of each filtered file in the locker dir to CSVs grouped by its leading folders
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Hash the locker files
    success = hashing.hash_locker_files(
        locker_base_directory = args.locker_base_directory,
        include_filter = args.include_filter,
        exclude_filter = args.exclude_filter,
        include_hidden = args.include_hidden,
        depth = args.depth,
        verbose = args.verbose,
        pretend_run = args.pretend_run)
    if not success:
        sys.exit(1)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
