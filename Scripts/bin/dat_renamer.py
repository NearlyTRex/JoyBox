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
args, unknown = parser.parse_known_args()
if not args.input_path:
    parser.print_help()
    sys.exit(-1)

# Check that input path exists first
input_path = os.path.realpath(args.input_path)
if not os.path.exists(input_path):
    system.LogError("Path '%s' does not exist" % args.input_path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Create game dat
    game_dat = dat.Dat()
    if os.path.isdir(args.dat_directory):
        game_dat.import_clrmamepro_dat_files(args.dat_directory, verbose = verbose, exit_on_failure = exit_on_failure)

    # Rename files
    game_dat.rename_files(input_path, verbose = verbose, exit_on_failure = exit_on_failure)

# Start
main()
