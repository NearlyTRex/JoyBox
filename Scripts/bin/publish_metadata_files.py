#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import collection
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Publish metadata files.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Build new published file for each category
    for game_supercategory in config.Supercategory.members():
        for game_category in config.Category.members():
            success = collection.PublishMetadataEntries(
                game_supercategory = game_supercategory,
                game_category = game_category,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if not success:
                system.LogErrorAndQuit("Publish of category '%s' failed" % game_category)

# Start
main()
