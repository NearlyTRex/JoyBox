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

# Parse arguments
parser = argparse.ArgumentParser(description="Dat renamer.")
parser.add_argument("input_path", type=str, help="Input path")
parser.add_argument("-d", "--dat_directory", type=str, help="Dat directory")
parser.add_argument("-c", "--dat_cachefile", type=str, help="Dat cachefile")
parser.add_argument("-g", "--generate_cachefile", action="store_true", help="Generate collected cachefile (if scanning normal dats)")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.input_path:
    parser.print_help()
    system.QuitProgram()

# Get input path
input_path = os.path.realpath(args.input_path)
if not os.path.isdir(input_path):
    system.LogErrorAndQuit("Path '%s' does not exist" % args.input_path)

# Get dat directory
dat_directory = ""
if args.dat_directory:
    dat_directory = os.path.realpath(args.dat_directory)

# Get dat cachefile
dat_cachefile = ""
if args.dat_cachefile:
    dat_cachefile = os.path.realpath(args.dat_cachefile)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Load game dat(s)
    game_dat = dat.Dat()
    if os.path.isdir(dat_directory):
        game_dat.import_clrmamepro_dat_files(
            dat_dir = dat_directory,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)
        if args.generate_cachefile:
            game_dat.export_cache_dat_file(
                dat_file = dat_cachefile,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
    elif os.path.isfile(dat_cachefile):
        game_dat.import_cache_dat_file(
            dat_file = dat_cachefile,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # Rename files
    game_dat.rename_files(
        input_dir = input_path,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

# Start
main()
