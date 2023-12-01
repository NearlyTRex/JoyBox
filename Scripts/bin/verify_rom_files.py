#!/usr/bin/env python3

# Imports
import os
import os.path
import sys
import argparse
import pathlib

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import system
import metadata
import hashing
import setup

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Verify metadata files
    for game_category in metadata.GetMetadataCategories():
        for game_subcategory in metadata.GetMetadataSubcategories(game_category):

            # Verify gamelist roms
            gamelist_file = metadata.DeriveMetadataFile(game_category, game_subcategory, config.metadata_format_gamelist)
            if os.path.isfile(gamelist_file):
                metadata_gamelist = metadata.Metadata()
                metadata_gamelist.import_from_gamelist_file(gamelist_file)
                metadata_gamelist.verify_roms()

            # Verify pegasus roms
            pegasus_file = metadata.DeriveMetadataFile(game_category, game_subcategory, config.metadata_format_pegasus)
            if os.path.isfile(pegasus_file):
                metadata_pegasus = metadata.Metadata()
                metadata_pegasus.import_from_pegasus_file(pegasus_file)
                metadata_pegasus.verify_roms()

    # Verify json files
    for game_category in metadata.GetMetadataCategories():
        for game_subcategory in sorted(metadata.GetMetadataSubcategories(game_category)):
            game_platform = metadata.DeriveMetadataPlatform(game_category, game_subcategory)
            for game_name in environment.GetGameNames(environment.GetJsonRomsMetadataRootDir(), game_category, game_subcategory):

                # Get json file path
                json_file_path = environment.GetJsonRomMetadataFile(game_category, game_subcategory, game_name)
                if not os.path.exists(json_file_path):
                    continue

                # Read json file
                json_file_data = system.ReadJsonFile(
                    src = json_file_path,
                    verbose = config.default_flag_verbose,
                    exit_on_failure = config.default_flag_exit_on_failure)

                # Get json info
                json_file_list = None
                json_launch_file = None
                json_transform_file = None
                if config.general_key_files in json_file_data:
                    json_file_list = json_file_data[config.general_key_files]
                if config.general_key_launch_file in json_file_data:
                    json_launch_file = json_file_data[config.general_key_launch_file]
                if config.general_key_transform_file in json_file_data:
                    json_transform_file = json_file_data[config.general_key_transform_file]

                # Files to check
                files_to_check = []

                # Add file lists
                if isinstance(json_file_list, list):
                    files_to_check += json_file_list

                # Add launch files
                if json_launch_file and not json_transform_file:
                    if isinstance(json_launch_file, list):
                        files_to_check += json_launch_file
                    elif isinstance(json_launch_file, str):
                        files_to_check += [json_launch_file]

                # Add transform files
                if json_launch_file and json_transform_file:
                    if isinstance(json_transform_file, list):
                        files_to_check += json_transform_file
                    elif isinstance(json_transform_file, str):
                        files_to_check += [json_transform_file]

                # Each of these files should exist
                for file_to_check in files_to_check:
                    stored_file = os.path.join(environment.GetRomDir(game_category, game_subcategory, game_name), file_to_check)
                    if not os.path.exists(stored_file):
                        print("File '%s' referenced in json file not found" % file_to_check)
                        sys.exit(1)

    # Verify hash files
    for game_supercategory in config.game_supercategories:
        for game_category in metadata.GetMetadataCategories():
            for game_subcategory in sorted(metadata.GetMetadataSubcategories(game_category)):

                # Get hash file path
                hash_file_path = environment.GetHashesMetadataFile(game_supercategory, game_category, game_subcategory)
                if not os.path.exists(hash_file_path):
                    continue

                # Read hash file
                print("Checking hash file '%s' ..." % hash_file_path)
                hash_file_data = hashing.ReadHashFile(hash_file_path)
                for hash_reference_file in hash_file_data.keys():

                    # Check if file exists
                    stored_file = os.path.join(environment.GetGamingStorageRootDir(), hash_reference_file)
                    if not os.path.exists(stored_file):
                        print("File '%s' referenced in hash file not found" % stored_file)
                        sys.exit(1)

# Start
environment.RunAsRootIfNecessary(main)
