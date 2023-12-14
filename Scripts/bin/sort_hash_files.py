#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import metadata
import hashing
import setup

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Paths
    hashes_base_dir = environment.GetHashesMetadataRootDir()

    # Sort hash files
    for file_supercategory in metadata.GetMetadataSupercategories():
        for file_category in metadata.GetMetadataCategories():
            for file_subcategory in metadata.GetMetadataSubcategories(file_category):

                # Get hash file
                hash_file = os.path.join(hashes_base_dir, file_supercategory, file_category, file_subcategory + ".txt")
                if not os.path.isfile(hash_file):
                    continue

                # Sort hash file
                hashing.SortHashFile(hash_file)

# Start
main()
