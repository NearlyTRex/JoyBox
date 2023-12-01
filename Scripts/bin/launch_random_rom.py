#!/usr/bin/env python3

# Imports
import os
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import metadata
import launcher
import setup

# Setup argument parser
parser = argparse.ArgumentParser(description="Launch random ROM.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-c", "--category", type=str, help="Rom category")
parser.add_argument("-s", "--subcategory", type=str, help="Rom subcategory")

# Parse arguments
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Set filter options
    filter_options = {}
    filter_options[config.filter_launchable_only] = True

    # Get random game
    game_entry = metadata.ChooseRandomGame(
        rom_category = args.category,
        rom_subcategory = args.subcategory,
        filter_options = filter_options)
    if not game_entry:
        print("Unable to select random game for launching")
        sys.exit(1)

    # Launch game
    launcher.LaunchGame(
        launch_platform = game_entry[config.metadata_key_platform],
        file_path = game_entry[config.metadata_key_file],
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

# Start
environment.RunAsRootIfNecessary(main)
