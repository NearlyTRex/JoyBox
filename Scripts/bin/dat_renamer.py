#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.environment as environment
import joybox.dat as dat
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Rename ROM files to the names a DAT file gives them, matching by MD5.",
    details = (
        "Loads ROM records from either every clrmamepro XML `.dat` file under `-d` (searched\n"
        "recursively), or a cache file given with `-c`; `-d` wins when both are given. Records\n"
        "without a name, size, CRC and MD5 are ignored.\n"
        "\n"
        "Then every file under `-i`, recursively, is hashed with MD5. A file whose hash matches\n"
        "a record is renamed, in its own directory, to the ROM file name from that record.\n"
        "Files with no match are left alone.\n"
        "\n"
        "With `-d` and `-g`, the collected records are also written to the `-c` path so later\n"
        "runs can load them with `-c` alone. The cache holds one ROM per line as\n"
        "`game || file || size || crc || md5`."),
    examples = [
        ("Rename using a folder of DAT files", "dat_renamer -i ~/Roms/Unsorted -d ~/Dats"),
        ("Rename and save a cache of the DAT records", "dat_renamer -i ~/Roms/Unsorted -d ~/Dats -g -c ~/Dats/cache.txt"),
        ("Rename using a saved cache", "dat_renamer -i ~/Roms/Unsorted -c ~/Dats/cache.txt"),
        ("Dry run", "dat_renamer -i ~/Roms/Unsorted -d ~/Dats -p -v"),
    ],
    notes = [
        "When two DAT records share an MD5, the one read last is used.",
        "A renamed file replaces any file already at the new name.",
    ],
    see_also = ["sanitize_filenames", "verify_game_files"],
    section = "Game ROMs & Images")
parser.add_input_path_argument(description = "Directory of files to rename, searched recursively. Required")
parser.add_string_argument(args = ("-d", "--dat_directory"), description = "Directory of clrmamepro XML `.dat` files to read ROM records from")
parser.add_string_argument(args = ("-c", "--dat_cachefile"), description = "Cache file to read ROM records from, or with `-g` to write them to")
parser.add_boolean_argument(args = ("-g", "--generate_cachefile"), description = "With `-d`, write the collected records to the `-c` cache file")
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

    # Get dat directory
    dat_directory = ""
    if args.dat_directory:
        dat_directory = os.path.realpath(args.dat_directory)

    # Get dat cachefile
    dat_cachefile = ""
    if args.dat_cachefile:
        dat_cachefile = os.path.realpath(args.dat_cachefile)

    # Show preview
    if not args.no_preview:
        details = ["Input path: %s" % input_path]
        if dat_directory:
            details.append("DAT directory: %s" % dat_directory)
        if dat_cachefile:
            details.append("DAT cachefile: %s" % dat_cachefile)
        if not prompts.prompt_for_preview("Rename files using DAT", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Load game dat(s)
    game_dat = dat.Dat()
    if paths.is_path_directory(dat_directory):
        game_dat.import_clrmamepro_dat_files(
            dat_dir = dat_directory,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if args.generate_cachefile:
            game_dat.export_cache_dat_file(
                dat_file = dat_cachefile,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
    elif paths.is_path_file(dat_cachefile):
        game_dat.import_cache_dat_file(
            dat_file = dat_cachefile,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Rename files
    game_dat.rename_files(
        input_dir = input_path,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
