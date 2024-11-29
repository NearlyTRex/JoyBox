#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import metadata
import environment
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Sort metadata files.")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Sort metadata files
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:

            # Get metadata file
            metadata_file = environment.GetMetadataFile(game_category, game_subcategory)
            if not os.path.isfile(metadata_file):
                continue

            # Sort metadata
            system.Log("Sorting metadata files for %s - %s..." % (game_category, game_subcategory))
            metadata_obj = metadata.Metadata()
            metadata_obj.import_from_metadata_file(metadata_file)
            metadata_obj.export_to_metadata_file(metadata_file)

# Start
main()
