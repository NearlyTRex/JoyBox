#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import metadata
import environment
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Clean metadata files.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Sort metadata files
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:

            # Get metadata file
            metadata_file = environment.GetMetadataFile(game_category, game_subcategory)
            if not system.IsPathFile(metadata_file):
                continue

            # Sort metadata
            system.LogInfo("Sorting metadata files for %s - %s..." % (game_category, game_subcategory))
            metadata_obj = metadata.Metadata()
            metadata_obj.import_from_metadata_file(metadata_file)
            metadata_obj.export_to_metadata_file(metadata_file)

# Start
main()
