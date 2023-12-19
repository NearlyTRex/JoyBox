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
import system
import metadata
import hashing
import gameinfo
import setup
import ini

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Find extra json files
    for json_file in system.BuildFileListByExtensions(environment.GetJsonMetadataRootDir(), extensions = [".json"]):

        # Check if json file matches up to a real rom path
        print("Checking if rom matching '%s' exists ..." % json_file)
        game_supercategory, game_category, game_subcategory = metadata.DeriveMetadataCategoriesFromFile(json_file)
        game_name = metadata.DeriveGameNameFromPath(json_file)
        game_rom_dir = environment.GetRomDir(game_category, game_subcategory, game_name)
        if not os.path.exists(game_rom_dir):
            print("Extraneous json file '%s' found" % json_file)
            sys.exit(1)

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
            for game_name in metadata.GetPossibleGameNames(environment.GetJsonRomsMetadataRootDir(), game_category, game_subcategory):

                # Get json file path
                json_file_path = environment.GetJsonRomMetadataFile(game_category, game_subcategory, game_name)
                if not os.path.exists(json_file_path):
                    continue

                # Read json file
                json_data = gameinfo.ParseGameJson(
                    json_file = json_file_path,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

                # Get json info
                json_file_list = json_data[config.json_key_files]
                json_launch_file = json_data[config.json_key_launch_file]
                json_transform_file = json_data[config.json_key_transform_file]

                # Files to check
                files_to_check = []

                # Add files
                files_to_check += json_file_list
                if len(json_transform_file):
                    files_to_check += json_transform_file
                else:
                    files_to_check += json_launch_file

                # Each of these files should exist
                for file_to_check in files_to_check:
                    stored_file = os.path.join(environment.GetRomDir(game_category, game_subcategory, game_name), file_to_check)
                    if not os.path.exists(stored_file):
                        print("File '%s' referenced in json file not found" % file_to_check)
                        sys.exit(1)

    # Verify hash files
    for game_supercategory in metadata.GetMetadataSupercategories():
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
main()
