#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import metadata
import setup

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Sort metadata files
    for game_category in metadata.GetMetadataCategories():
        for game_subcategory in metadata.GetMetadataSubcategories(game_category):

            # Get pegasus file
            pegasus_file = metadata.DeriveMetadataFile(game_category, game_subcategory, config.metadata_format_pegasus)
            if not os.path.isfile(pegasus_file):
                continue

            # Sort pegasus file
            metadata_pegasus = metadata.Metadata()
            metadata_pegasus.import_from_pegasus_file(pegasus_file)
            metadata_pegasus.sync_assets()
            metadata_pegasus.export_to_pegasus_file(pegasus_file)

# Start
main()
