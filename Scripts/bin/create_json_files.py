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
import gameinfo
import platforms
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
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:
            game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
            for game_name in gameinfo.FindAllGameNames(environment.GetRomRootDir(), game_category, game_subcategory):
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

                # Set json value
                def SetJsonValue(json_key, json_value):
                    if platforms.IsAutoFillJsonKey(game_platform, json_key):
                        json_file_data[json_key] = json_value
                    elif platforms.IsFillOnceJsonKey(game_platform, json_key):
                        if json_key not in json_file_data:
                            json_file_data[json_key] = json_value

                # Get all files
                all_files = system.BuildFileList(
                    root = base_rom_path,
                    use_relative_paths = True)

                # Get best game file
                best_game_file = gameinfo.FindBestGameFile(base_rom_path)
                best_game_file = system.GetFilenameFile(best_game_file)

                # Find computer installers
                computer_installers = []
                for file in system.GetDirectoryContents(base_rom_path):
                    if file.endswith(".exe"):
                        computer_installers = [os.path.join(config.token_setup_main_root, file)]
                        break
                for file in system.GetDirectoryContents(base_rom_path):
                    if file.endswith(".msi"):
                        computer_installers = [os.path.join(config.token_setup_main_root, file)]
                        break

                # Find computer dlc installers
                computer_dlc_installers = system.BuildFileListByExtensions(
                    root = os.path.join(base_rom_path, "dlc"),
                    extensions = config.computer_program_extensions,
                    new_relative_path = os.path.join(config.token_setup_main_root, "dlc"),
                    use_relative_paths = True)

                # Find computer update installers
                computer_update_installers = system.BuildFileListByExtensions(
                    root = os.path.join(base_rom_path, "update"),
                    extensions = config.computer_program_extensions,
                    new_relative_path = os.path.join(config.token_setup_main_root, "update"),
                    use_relative_paths = True)

                # Find computer extras
                computer_extras = system.BuildFileList(
                    root = os.path.join(base_rom_path, "extra"),
                    new_relative_path = os.path.join(config.token_setup_main_root, "extra"),
                    use_relative_paths = True)

                # Computer
                if game_category == config.game_category_computer:
                    SetJsonValue(config.json_key_installer_exe, computer_installers)
                    SetJsonValue(config.json_key_dlc, computer_dlc_installers)
                    SetJsonValue(config.json_key_update, computer_update_installers)
                    SetJsonValue(config.json_key_extra, computer_extras)
                    SetJsonValue(config.json_key_transform_file, best_game_file)

                # Other platforms
                else:
                    SetJsonValue(config.json_key_files, all_files)
                    SetJsonValue(config.json_key_launch_name, "REPLACEME")
                    SetJsonValue(config.json_key_launch_file, best_game_file)
                    SetJsonValue(config.json_key_transform_file, best_game_file)

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
main()
