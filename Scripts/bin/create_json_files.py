#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import json
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import metadata
import transform
import system
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Create or update json files.")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Create json files
    for game_category in metadata.GetMetadataCategories():
        for game_subcategory in sorted(metadata.GetMetadataSubcategories(game_category)):
            game_platform = metadata.DeriveMetadataPlatform(game_category, game_subcategory)
            for game_name in metadata.GetPossibleGameNames(environment.GetRomRootDir(), game_category, game_subcategory):
                base_rom_path = environment.GetRomDir(game_category, game_subcategory, game_name)

                # Get json file path
                json_file_path = environment.GetJsonRomMetadataFile(game_category, game_subcategory, game_name)

                # Build json data
                json_file_data = {}

                # Already existing json file
                if os.path.exists(json_file_path):
                    json_file_data = system.ReadJsonFile(
                        src = json_file_path,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)

                # Set transform file
                needs_transform_file = transform.IsTransformRequired(game_platform)
                has_transform_file = config.general_key_transform_file in json_file_data
                if needs_transform_file and not has_transform_file:
                    best_game_file = metadata.FindBestGameFile(base_rom_path)
                    best_game_file = system.GetFilenameFile(best_game_file)
                    json_file_data[config.general_key_transform_file] = best_game_file

                # Computer
                if game_category == config.game_category_computer:

                    # Get rom data
                    rom_dlc_path = os.path.join(base_rom_path, "dlc")
                    rom_update_path = os.path.join(base_rom_path, "update")
                    rom_extra_path = os.path.join(base_rom_path, "extra")

                    # Try to find the best installer exe
                    rom_installer_exe = game_name + ".exe"
                    for file in system.GetDirectoryContents(base_rom_path):
                        if file.endswith(".exe"):
                            rom_installer_exe = file
                            break
                    for file in system.GetDirectoryContents(base_rom_path):
                        if file.endswith(".msi"):
                            rom_installer_exe = file
                            break

                    # Try to find all the dlc
                    rom_dlc_installers = system.BuildFileListByExtensions(
                        root = rom_dlc_path,
                        extensions = config.computer_program_extensions,
                        new_relative_path = os.path.join(config.token_setup_main_root, "dlc"),
                        use_relative_paths = True)

                    # Try to find all the updates
                    rom_update_installers = system.BuildFileListByExtensions(
                        root = rom_update_path,
                        extensions = config.computer_program_extensions,
                        new_relative_path = os.path.join(config.token_setup_main_root, "update"),
                        use_relative_paths = True)

                    # Try to find all the extras
                    rom_extras = system.BuildFileList(
                        root = rom_extra_path,
                        new_relative_path = os.path.join(config.token_setup_main_root, "extra"),
                        use_relative_paths = True)

                    # Try to set cwd
                    has_main_game_exe = config.computer_key_main_game_exe in json_file_data
                    has_main_game_exe_cwd = config.computer_key_main_game_exe_cwd in json_file_data
                    if has_main_game_exe and not has_main_game_exe_cwd:
                        json_file_data[config.computer_key_main_game_exe_cwd] = {}
                        for main_game_exe in json_file_data[config.computer_key_main_game_exe]:
                            json_file_data[config.computer_key_main_game_exe_cwd][main_game_exe] = system.GetFilenameDirectory(main_game_exe)

                    # Set initial json data
                    if game_subcategory != "Disc":
                        json_file_data[config.computer_key_installer_exe] = [os.path.join(config.token_setup_main_root, rom_installer_exe)]
                        json_file_data[config.computer_key_dlc] = rom_dlc_installers
                        json_file_data[config.computer_key_update] = rom_update_installers
                        json_file_data[config.computer_key_extra] = rom_extras

                # Other platforms
                else:

                    # Set files
                    json_file_data[config.general_key_files] = system.BuildFileList(
                        root = base_rom_path,
                        use_relative_paths = True)

                    # Try to set launch name
                    needs_launch_name = platforms.IsLaunchedByName(game_platform)
                    has_launch_name = config.general_key_launch_name in json_file_data
                    if needs_launch_name and not has_launch_name:
                        json_file_data[config.general_key_launch_name] = "REPLACEME"

                    # Try to set launch file
                    needs_launch_file = platforms.IsLaunchedByFile(game_platform)
                    has_launch_file = config.general_key_launch_file in json_file_data
                    if needs_launch_file and not has_launch_file:
                        best_game_file = metadata.FindBestGameFile(base_rom_path)
                        best_game_file = system.GetFilenameFile(best_game_file)
                        json_file_data[config.general_key_launch_file] = best_game_file

                # Write json file
                system.MakeDirectory(
                    dir = system.GetFilenameDirectory(json_file_path),
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
                system.WriteJsonFile(
                    src = json_file_path,
                    json_data = json_file_data,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

                # Clean json file
                system.CleanJsonFile(
                    src = json_file_path,
                    sort_keys = True,
                    remove_empty_values = True,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

# Start
environment.RunAsRootIfNecessary(main)
