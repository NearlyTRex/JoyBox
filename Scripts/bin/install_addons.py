#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import gameinfo
import addon
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Install addons.")
parser.add_input_path_argument()
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = parser.get_input_path()

    # Get json file
    json_files = [input_path]
    if system.IsPathDirectory(input_path):
        json_files = system.BuildFileListByExtensions(input_path, extensions = [".json"])

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
