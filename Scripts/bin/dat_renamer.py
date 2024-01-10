#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import environment
import dat
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Dat renamer.")
parser.add_argument("input_path", help="Input path")
parser.add_argument("-d", "--dat_directory", type=str, help="Dat directory")
parser.add_argument("-c", "--dat_cachefile", type=str, help="Dat cachefile")
parser.add_argument("-g", "--generate_cachefile", action="store_true", help="Generate collected cachefile (if scanning normal dats)")
args, unknown = parser.parse_known_args()
if not args.input_path:
    parser.print_help()
    sys.exit(-1)

# Check that input path exists first
input_path = os.path.realpath(args.input_path)
if not os.path.isdir(input_path):
    system.LogError("Path '%s' does not exist" % args.input_path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Load game dat(s)
    game_dat = dat.Dat()
    if os.path.isdir(args.dat_directory):
        game_dat.import_clrmamepro_dat_files(
            dat_dir = args.dat_directory,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if args.generate_cachefile:
            game_dat.export_cache_dat_file(
                dat_file = args.dat_cachefile,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
    elif os.path.isfile(args.dat_cachefile):
        game_dat.import_cache_dat_file(
            dat_file = args.dat_cachefile,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Rename files
    game_dat.rename_files(
        input_dir = input_path,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Start
main()
