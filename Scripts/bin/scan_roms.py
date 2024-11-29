#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import command
import system
import environment
import gameinfo
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Scan roms.")
parser.add_argument("-e", "--source_type",
    choices=config.source_types,
    default=config.source_type_remote,
    help="Source types"
)
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Scripts
    build_metadata_file_bin = os.path.join(environment.GetScriptsBinDir(), "build_metadata_file" + environment.GetScriptsCommandExtension())
    publish_metadata_files_bin = os.path.join(environment.GetScriptsBinDir(), "publish_metadata_files" + environment.GetScriptsCommandExtension())
    sort_metadata_files_bin = os.path.join(environment.GetScriptsBinDir(), "sort_metadata_files" + environment.GetScriptsCommandExtension())

    # Build metadata for each category/subcategory
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:
            game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

            # Metadata info
            scan_rom_path = os.path.join(environment.GetLockerGamingRomsRootDir(args.source_type), game_category, game_subcategory)
            metadata_file = environment.GetMetadataFile(game_category, game_subcategory)

            # Build metadata
            if os.path.isdir(scan_rom_path):
                system.Log("Building metadata [Category: '%s', Subcategory: '%s'] ..." % (game_category, game_subcategory))
                build_game_list_cmd = [
                    build_metadata_file_bin,
                    "-c", game_category,
                    "-s", game_subcategory,
                    "-o", metadata_file,
                    scan_rom_path
                ]
                command.RunCheckedCommand(
                    cmd = build_game_list_cmd,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

    # Sort metadata files
    system.Log("Sorting metadata files ...")
    command.RunCheckedCommand(
        cmd = sort_metadata_files_bin,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

    # Publish metadata files
    system.Log("Publishing metadata files ...")
    command.RunCheckedCommand(
        cmd = publish_metadata_files_bin,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
main()
