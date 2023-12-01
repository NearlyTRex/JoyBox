#!/usr/bin/env python3

# Imports
import os
import os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import command
import environment
import metadata
import system
import setup

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Scripts
    build_metadata_file_bin = os.path.join(environment.GetGameScriptsBinDir(), "build_metadata_file" + environment.GetGameScriptsCommandExtension())
    publish_metadata_files_bin = os.path.join(environment.GetGameScriptsBinDir(), "publish_metadata_files" + environment.GetGameScriptsCommandExtension())
    add_missing_metadata_bin = os.path.join(environment.GetGameScriptsBinDir(), "add_missing_metadata" + environment.GetGameScriptsCommandExtension())
    sort_metadata_files_bin = os.path.join(environment.GetGameScriptsBinDir(), "sort_metadata_files" + environment.GetGameScriptsCommandExtension())

    # Build metadata for each category/subcategory
    for game_category in metadata.GetMetadataCategories():
        for game_subcategory in metadata.GetMetadataSubcategories(game_category):
            game_platform = metadata.DeriveMetadataPlatform(game_category, game_subcategory)

            # Metadata info
            local_rom_path = os.path.join(environment.GetRomRootDir(), game_category, game_subcategory)
            metadata_file = metadata.DeriveMetadataFile(game_category, game_subcategory, config.metadata_format_gamelist)

            # Build metadata
            print("Building metadata [Category: '%s', Subcategory: '%s'] ..." % (game_category, game_subcategory))
            build_game_list_cmd = [
                build_metadata_file_bin,
                "-f", config.metadata_format_gamelist,
                "-c", game_category,
                "-s", game_subcategory,
                "-o", metadata_file,
            ]

            build_game_list_cmd += [
                "-j",
                local_rom_path
            ]
            command.RunCheckedCommand(
                cmd = build_game_list_cmd,
                verbose = True)

    # Add missing metadata
    print("Adding missing metadata ...")
    command.RunCheckedCommand(
        cmd = add_missing_metadata_bin,
        verbose = True)

    # Sort metadata files
    print("Sorting metadata files ...")
    command.RunCheckedCommand(
        cmd = sort_metadata_files_bin,
        verbose = True)

    # Publish metadata files
    print("Publishing metadata files ...")
    command.RunCheckedCommand(
        cmd = publish_metadata_files_bin,
        verbose = True)

# Start
environment.RunAsRootIfNecessary(main)
