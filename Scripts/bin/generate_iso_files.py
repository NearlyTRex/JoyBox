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
import environment
import metadata
import hashing
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Generate iso files.")
parser.add_argument("-u", "--file_supercategory",
    choices=config.game_supercategories,
    default=config.game_supercategory_roms,
    help="File supercategory"
)
parser.add_argument("-c", "--file_category", type=str, help="File category")
parser.add_argument("-s", "--file_subcategory", type=str, help="File subcategory")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Paths
hashes_base_dir = os.path.join(environment.GetHashesMetadataRootDir(), args.file_supercategory)
files_root_dir = environment.GetLockerGamingSupercategoryRootDir(args.file_supercategory)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get file groupings
    def GetFileGroupings(hash_filenames, max_group_size):

        # Group results
        results = {}

        # Add empty group
        def add_empty_group(group_name):
            results[group_name] = {}
            results[group_name]["size"] = 0
            results[group_name]["files"] = []

        # Groups info
        group_counter = 1
        group_name = "Group" + str(group_counter)
        previous_basename = ""
        current_basename = ""

        # Create initial group
        add_empty_group(group_name)

        # Aggregate similar files together into sets
        hash_sets = {}
        for hash_filename in sorted(hash_filenames):
            hash_contents = hashing.ReadHashFile(hash_filename)
            for hash_key in sorted(hash_contents.keys()):
                file_location = hash_key
                file_directory = system.GetFilenameDirectory(file_location)
                file_size = int(hash_contents[hash_key]["size"])
                if not file_directory in hash_sets:
                    hash_sets[file_directory] = {}
                    hash_sets[file_directory]["size"] = 0
                    hash_sets[file_directory]["files"] = []
                hash_sets[file_directory]["size"] += file_size
                hash_sets[file_directory]["files"].append(file_location)

        # Add to each group based on sizing
        for hash_set_key in sorted(hash_sets.keys()):
            hash_set_size = hash_sets[hash_set_key]["size"]
            hash_set_files = hash_sets[hash_set_key]["files"]

            # Check if we need to start a new group
            if hash_set_size + results[group_name]["size"] > max_group_size:
                group_counter += 1
                group_name = "Group" + str(group_counter)
                add_empty_group(group_name)

            # Add to group
            results[group_name]["size"] += hash_set_size
            results[group_name]["files"] += hash_set_files

        # Return groups
        return results

    # Get hash files
    hash_files = []
    if args.file_category and args.file_subcategory:
        hash_files.append(os.path.join(hashes_base_dir, args.file_category, args.file_subcategory + ".txt"))
    elif args.file_category:
        for file_subcategory in config.game_subcategories[args.file_category]:
            hash_files.append(os.path.join(files_root_dir, args.file_category, file_subcategory))
    else:
        for file_category in config.game_categories:
            for file_subcategory in config.game_subcategories[file_category]:
                hash_files.append(os.path.join(files_root_dir, file_category, file_subcategory))

    # Generate iso files
    if hash_files:
        out = GetFileGroupings(hash_files, config.max_disc_data_size_100gb)
        for key in out.keys():
            print(key, out[key]["size"])
            for file_entry in out[key]["files"]:
                print(file_entry)

# Start
main()
