#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import gameinfo
import addon
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Install addons.")
parser.add_argument("path", help="Input path")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    system.QuitProgram()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get json file
    json_files = [args.path]
    if os.path.isdir(args.path):
        json_files = system.BuildFileListByExtensions(args.path, extensions = [".json"])

    # Install addons
    for json_file in json_files:

        # Get game info
        game_info = gameinfo.GameInfo(
            json_file = json_file,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

        # Install addons
        addon.InstallAddons(
            game_info = game_info,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
main()
