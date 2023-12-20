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

    # Add missing games for each category/subcategory
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:

            # Get gamelist file
            gamelist_file = environment.GetMetadataFile(game_category, game_subcategory, config.metadata_format_gamelist)
            if not os.path.isfile(gamelist_file):
                continue

            # Get pegasus file
            pegasus_file = environment.GetMetadataFile(game_category, game_subcategory, config.metadata_format_pegasus)
            if not os.path.isfile(pegasus_file):
                continue

            # Read gamelist file
            metadata_gamelist = metadata.Metadata()
            metadata_gamelist.import_from_gamelist_file(gamelist_file)

            # Read pegasus file
            metadata_pegasus = metadata.Metadata()
            metadata_pegasus.import_from_pegasus_file(pegasus_file)

            # Merge metadata objects
            metadata_gamelist.merge_contents(metadata_pegasus)
            metadata_pegasus.merge_contents(metadata_gamelist)

            # Write back files
            metadata_gamelist.export_to_gamelist_file(gamelist_file)
            metadata_pegasus.export_to_pegasus_file(pegasus_file)

# Start
main()
