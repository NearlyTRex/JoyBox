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

# Parse arguments
parser = argparse.ArgumentParser(description="Create or update json files.")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Create json files
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:
            game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
            for game_name in gameinfo.FindAllGameNames(environment.GetLockerGamingRomsRootDir(config.source_type_remote), game_category, game_subcategory):
                base_rom_path = environment.GetLockerGamingRomDir(game_category, game_subcategory, game_name)

                # Get json file path
                json_file_path = environment.GetJsonRomMetadataFile(game_category, game_subcategory, game_name)

                # Build json data
                json_file_data = {}

                # Already existing json file
                if os.path.exists(json_file_path):
                    json_file_data = system.ReadJsonFile(
                        src = json_file_path,
                        verbose = args.verbose,
                        exit_on_failure = args.exit_on_failure)

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

                # Get all dlc
                all_dlc = system.BuildFileList(
                    root = os.path.join(base_rom_path, config.json_key_dlc),
                    use_relative_paths = True)

                # Get all updates
                all_updates = system.BuildFileList(
                    root = os.path.join(base_rom_path, config.json_key_update),
                    use_relative_paths = True)

                # Get all extras
                all_extras = system.BuildFileList(
                    root = os.path.join(base_rom_path, config.json_key_extra),
                    use_relative_paths = True)

                # Get all dependencies
                all_dependencies = system.BuildFileList(
                    root = os.path.join(base_rom_path, config.json_key_dependencies),
                    use_relative_paths = True)

                # Get best game file
                best_game_file = gameinfo.FindBestGameFile(base_rom_path)
                best_game_file = system.GetFilenameFile(best_game_file)

                # Find computer installers
                computer_installers = []
                for file in system.GetDirectoryContents(base_rom_path):
                    if file.endswith(".exe"):
                        computer_installers += [os.path.join(config.token_setup_main_root, file)]
                for file in system.GetDirectoryContents(base_rom_path):
                    if file.endswith(".msi"):
                        computer_installers += [os.path.join(config.token_setup_main_root, file)]
                        break

                # Find computer update installers
                computer_update_installers = system.BuildFileListByExtensions(
                    root = os.path.join(base_rom_path, "update"),
                    extensions = config.computer_program_extensions,
                    new_relative_path = os.path.join(config.token_setup_main_root, "update"),
                    use_relative_paths = True)
                computer_installers += computer_update_installers

                # Find computer dlc installers
                computer_dlc_installers = system.BuildFileListByExtensions(
                    root = os.path.join(base_rom_path, "dlc"),
                    extensions = config.computer_program_extensions,
                    new_relative_path = os.path.join(config.token_setup_main_root, "dlc"),
                    use_relative_paths = True)
                computer_installers += computer_dlc_installers

                # Common platforms
                SetJsonValue(config.json_key_files, all_files)
                SetJsonValue(config.json_key_dlc, all_dlc)
                SetJsonValue(config.json_key_update, all_updates)
                SetJsonValue(config.json_key_extra, all_extras)
                SetJsonValue(config.json_key_dependencies, all_dependencies)
                SetJsonValue(config.json_key_transform_file, best_game_file)

                # Computer
                if game_category == config.game_category_computer:
                    SetJsonValue(config.json_key_installer_exe, computer_installers)
                    if game_subcategory == config.game_subcategory_amazon_games:
                        SetJsonValue(config.json_key_amazon, {
                            config.json_key_amazon_appid: "",
                            config.json_key_amazon_name: ""
                        })
                    elif game_subcategory == config.game_subcategory_gog:
                        SetJsonValue(config.json_key_gog, {
                            config.json_key_gog_appid: "",
                            config.json_key_gog_appname: ""
                        })
                    elif game_subcategory == config.game_subcategory_steam:
                        SetJsonValue(config.json_key_steam, {
                            config.json_key_steam_appid: "",
                            config.json_key_steam_branchid: "public"
                        })

                # Other platforms
                else:
                    SetJsonValue(config.json_key_launch_name, "REPLACEME")
                    SetJsonValue(config.json_key_launch_file, best_game_file)

                # Write json file
                system.MakeDirectory(
                    dir = system.GetFilenameDirectory(json_file_path),
                    verbose = args.verbose,
                    exit_on_failure = args.exit_on_failure)
                system.WriteJsonFile(
                    src = json_file_path,
                    json_data = json_file_data,
                    verbose = args.verbose,
                    exit_on_failure = args.exit_on_failure)

                # Clean json file
                system.CleanJsonFile(
                    src = json_file_path,
                    sort_keys = True,
                    remove_empty_values = True,
                    verbose = args.verbose,
                    exit_on_failure = args.exit_on_failure)

# Start
main()
