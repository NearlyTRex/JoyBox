#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import metadata
import setup

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

            # Sort metadata file
            metadata_obj = metadata.Metadata()
            metadata_obj.import_from_metadata_file(metadata_file)
            metadata_obj.sync_assets()
            metadata_obj.export_to_metadata_file(metadata_file)

# Start
main()
