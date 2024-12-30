#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import metadata
import hashing
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Generate iso files.")
parser.add_game_supercategory_argument()
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Paths
hashes_base_dir = os.path.join(environment.GetHashesMetadataRootDir(), args.game_supercategory)
files_root_dir = environment.GetLockerGamingSupercategoryRootDir(args.game_supercategory)

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
    if args.game_category and args.game_subcategory:
        hash_files.append(os.path.join(hashes_base_dir, args.game_category, args.game_subcategory + ".txt"))
    elif args.game_category:
        for game_subcategory in config.subcategory_map[args.game_category]:
            hash_files.append(os.path.join(files_root_dir, args.game_category, game_subcategory))
    else:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                hash_files.append(os.path.join(files_root_dir, game_category, game_subcategory))

    # Generate iso files
    if hash_files:
        out = GetFileGroupings(hash_files, config.max_disc_data_size_100gb)
        for key in out.keys():
            print(key, out[key]["size"])
            for file_entry in out[key]["files"]:
                print(file_entry)

# Start
main()
