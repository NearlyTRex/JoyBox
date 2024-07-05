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
import gameinfo
import system
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Find missing game assets.")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get search info
    assets_dir = environment.GetLockerGamingAssetsRootDir()
    metadata_dir = environment.GetPegasusMetadataRootDir()

    # Find all possible assets
    all_assets = set()
    for filename in system.BuildFileList(assets_dir):
        all_assets.add(filename)

    # Find missing assets
    found_assets = set()
    missing_assets = dict()
    for filename in system.BuildFileList(metadata_dir):
        if environment.IsMetadataFile(filename):

            # Load metadata
            metadata_obj = metadata.Metadata()
            metadata_obj.import_from_metadata_file(filename)
            for game_platform in metadata_obj.get_sorted_platforms():
                for game_entry in metadata_obj.get_sorted_entries(game_platform):
                    for asset_type in config.asset_types_all:

                        # Get game info
                        game_name = game_entry.get_game()
                        game_supercategory, game_category, game_subcategory = gameinfo.DeriveGameCategoriesFromPlatform(game_platform)

                        # Get asset file
                        asset_file = environment.GetLockerGameAssetFile(game_category, game_subcategory, game_name, asset_type)

                        # Check if asset exists
                        if os.path.exists(asset_file):
                            found_assets.add(asset_file)
                        else:
                            if not asset_type in missing_assets:
                                missing_assets[asset_type] = set()
                            missing_assets[asset_type].add(asset_file)

    # Write missing assets
    for asset_type in config.asset_types_all:
        with open("Missing_" + asset_type + ".txt", "w", encoding="utf8") as file:
            if asset_type in missing_assets:
                for missing_asset in sorted(missing_assets[asset_type]):
                    file.write("%s\n" % missing_asset)

    # Gather extra assets
    extra_assets = all_assets - found_assets
    for asset_type in config.asset_types_all:
        if asset_type in missing_assets:
            extra_assets = extra_assets - missing_assets[asset_type]

    # Write extra assets
    with open("Extras.txt", "w", encoding="utf8") as file:
        for extra_asset in sorted(extra_assets):
            file.write("%s\n" % extra_asset)

# Start
main()
