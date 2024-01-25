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
import hashing
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Sort hash files.")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Paths
    hashes_base_dir = environment.GetHashesMetadataRootDir()

    # Sort hash files
    for file_supercategory in config.game_supercategories:
        for file_category in config.game_categories:
            for file_subcategory in config.game_subcategories[file_category]:

                # Get hash file
                hash_file = os.path.join(hashes_base_dir, file_supercategory, file_category, file_subcategory + ".txt")
                if not os.path.isfile(hash_file):
                    continue

                # Sort hash file
                hashing.SortHashFile(hash_file)

# Start
main()
