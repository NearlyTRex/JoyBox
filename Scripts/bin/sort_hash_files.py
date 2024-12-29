#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import metadata
import hashing
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Sort hash files.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Paths
    hashes_base_dir = environment.GetHashesMetadataRootDir()

    # Sort hash files
    for game_supercategory in config.Supercategory.members():
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:

                # Get hash file
                hash_file = os.path.join(hashes_base_dir, game_supercategory, game_category, game_subcategory + ".txt")
                if not system.IsPathFile(hash_file):
                    continue

                # Sort hash file
                hashing.SortHashFile(hash_file)

# Start
main()
