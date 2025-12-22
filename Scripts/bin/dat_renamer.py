#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import dat
import arguments
import setup
import logger
import paths
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Dat renamer.")
parser.add_input_path_argument()
parser.add_string_argument(args = ("-d", "--dat_directory"), description = "Dat directory")
parser.add_string_argument(args = ("-c", "--dat_cachefile"), description = "Dat cachefile")
parser.add_boolean_argument(args = ("-g", "--generate_cachefile"), description = "Generate collected cachefile (if scanning normal dats)")
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
    system.RunMain(main)
