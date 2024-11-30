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

# Parse arguments
parser = argparse.ArgumentParser(description="Verify rom files.")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Find extra json files
    for json_file in system.BuildFileListByExtensions(environment.GetJsonMetadataRootDir(), extensions = [".json"]):

        # Check if json file matches up to a real game path
        system.Log("Checking if game matching '%s' exists ..." % json_file)
        game_supercategory, game_category, game_subcategory = gameinfo.DeriveGameCategoriesFromFile(json_file)
        game_name = system.GetFilenameBasename(json_file)
        game_base_dir = environment.GetLockerGamingRomDir(game_category, game_subcategory, game_name)
        if not os.path.exists(game_base_dir):
            system.LogErrorAndQuit("Extraneous json file '%s' found" % json_file)

    # Verify metadata files
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:
            metadata_file = environment.GetMetadataFile(game_category, game_subcategory)
            if os.path.isfile(metadata_file):
                metadata_obj = metadata.Metadata()
                metadata_obj.import_from_metadata_file(metadata_file)
                metadata_obj.verify_roms()

    # Verify json files
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:
            game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
            for game_name in gameinfo.FindAllGameNames(environment.GetJsonRomsMetadataRootDir(), game_category, game_subcategory):

                # Get json file
                json_file = environment.GetJsonRomMetadataFile(game_category, game_subcategory, game_name)
                if not os.path.exists(json_file):
                    continue

                # Get game info
                game_info = gameinfo.GameInfo(
                    json_file = json_file,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

                # Get game info
                json_file_list = game_info.get_files()
                json_launch_file = game_info.get_launch_file()
                json_transform_file = game_info.get_transform_file()

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
                    stored_file = os.path.join(environment.GetLockerGamingRomDir(game_category, game_subcategory, game_name), file_to_check)
                    if not os.path.exists(stored_file):
                        system.LogErrorAndQuit("File '%s' referenced in json file not found" % file_to_check)

    # Verify hash files
    for game_supercategory in config.game_supercategories:
        for game_category in config.game_categories:
            for game_subcategory in config.game_subcategories[game_category]:

                # Get hash file path
                hash_file_path = environment.GetHashesMetadataFile(game_supercategory, game_category, game_subcategory)
                if not os.path.exists(hash_file_path):
                    continue

                # Read hash file
                system.Log("Checking hash file '%s' ..." % hash_file_path)
                hash_file_data = hashing.ReadHashFile(hash_file_path)
                for hash_reference_file in hash_file_data.keys():

                    # Check if file exists
                    stored_file = os.path.join(environment.GetLockerGamingRootDir(), hash_reference_file)
                    if not os.path.exists(stored_file):
                        system.LogErrorAndQuit("File '%s' referenced in hash file not found" % stored_file)

# Start
main()
