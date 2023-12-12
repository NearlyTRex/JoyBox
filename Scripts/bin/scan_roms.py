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
import ini

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Scripts
    build_metadata_file_bin = os.path.join(environment.GetScriptsBinDir(), "build_metadata_file" + environment.GetScriptsCommandExtension())
    publish_metadata_files_bin = os.path.join(environment.GetScriptsBinDir(), "publish_metadata_files" + environment.GetScriptsCommandExtension())
    add_missing_metadata_bin = os.path.join(environment.GetScriptsBinDir(), "add_missing_metadata" + environment.GetScriptsCommandExtension())
    sort_metadata_files_bin = os.path.join(environment.GetScriptsBinDir(), "sort_metadata_files" + environment.GetScriptsCommandExtension())

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
                local_rom_path
            ]
            command.RunCheckedCommand(
                cmd = build_game_list_cmd,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Add missing metadata
    print("Adding missing metadata ...")
    command.RunCheckedCommand(
        cmd = add_missing_metadata_bin,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Sort metadata files
    print("Sorting metadata files ...")
    command.RunCheckedCommand(
        cmd = sort_metadata_files_bin,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Publish metadata files
    print("Publishing metadata files ...")
    command.RunCheckedCommand(
        cmd = publish_metadata_files_bin,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Start
environment.RunAsRootIfNecessary(main)
