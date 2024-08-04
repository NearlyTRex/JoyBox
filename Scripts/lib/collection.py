# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import gameinfo
import platforms
import system
import cryption

# Create game json file
def CreateGameJsonFile(
    file_category,
    file_subcategory,
    file_title,
    file_root = None,
    passphrase = None,
    verbose = False,
    exit_on_failure = False):

    # Get platform
    file_platform = gameinfo.DeriveGamePlatformFromCategories(file_category, file_subcategory)

    # Get base path
    base_path = environment.GetLockerGamingRomDir(file_category, file_subcategory, file_title)
    if system.IsPathValid(file_root):
        base_path = os.path.realpath(file_root)

    # Get json file path
    json_file_path = environment.GetJsonRomMetadataFile(file_category, file_subcategory, file_title)

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
        if platforms.IsAutoFillJsonKey(file_platform, json_key):
            json_file_data[json_key] = json_value
        elif platforms.IsFillOnceJsonKey(file_platform, json_key):
            if json_key not in json_file_data:
                json_file_data[json_key] = json_value

    # Get all files
    all_files = system.BuildFileList(base_path)
    if isinstance(passphrase, str) and len(passphrase) > 0:
        all_files = cryption.GetRealFilePaths(
            source_files = all_files,
            passphrase = passphrase,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Get rebased files
    rebased_files = system.ConvertFileListToRelativePaths(all_files, base_path)

    # Build path lists
    all_main = []
    all_dlc = []
    all_updates = []
    all_extras = []
    all_dependencies = []
    for rebased_file in rebased_files:
        rebased_subfile = system.GetFilenameFrontSlice(rebased_file)
        if rebased_file.startswith(config.json_key_dlc):
            all_dlc.append(rebased_subfile)
        elif rebased_file.startswith(config.json_key_update):
            all_updates.append(rebased_subfile)
        elif rebased_file.startswith(config.json_key_extra):
            all_extras.append(rebased_subfile)
        elif rebased_file.startswith(config.json_key_dependencies):
            all_dependencies.append(rebased_subfile)
        else:
            all_main.append(rebased_file)

    # Build exe lists
    exe_main = [f for f in all_main if f.endswith(".exe")]
    exe_dlc = [f for f in all_dlc if f.endswith(".exe")]
    exe_updates = [f for f in all_updates if f.endswith(".exe")]

    # Get top level paths
    top_level_paths = system.ConvertToTopLevelPaths(rebased_files)

    # Get best game file
    best_game_file = gameinfo.FindBestGameFile(top_level_paths)
    best_game_file = system.GetFilenameFile(best_game_file)

    # Get computer roots
    computer_root_dlc = os.path.join(config.token_setup_main_root, config.json_key_dlc)
    computer_root_updates = os.path.join(config.token_setup_main_root, config.json_key_update)

    # Get computer installers
    computer_installers = []
    computer_installers += system.ConvertFileListToAbsolutePaths(exe_main, config.token_setup_main_root)
    computer_installers += system.ConvertFileListToAbsolutePaths(exe_updates, computer_root_updates)
    computer_installers += system.ConvertFileListToAbsolutePaths(exe_dlc, computer_root_dlc)

    # Set common keys
    SetJsonValue(config.json_key_files, rebased_files)
    SetJsonValue(config.json_key_dlc, all_dlc)
    SetJsonValue(config.json_key_update, all_updates)
    SetJsonValue(config.json_key_extra, all_extras)
    SetJsonValue(config.json_key_dependencies, all_dependencies)
    SetJsonValue(config.json_key_transform_file, best_game_file)

    # Set computer keys
    if file_category == config.game_category_computer:
        SetJsonValue(config.json_key_installer_exe, computer_installers)
        if file_subcategory == config.game_subcategory_amazon_games:
            SetJsonValue(config.json_key_amazon, {
                config.json_key_amazon_appid: "",
                config.json_key_amazon_name: ""
            })
        elif file_subcategory == config.game_subcategory_gog:
            SetJsonValue(config.json_key_gog, {
                config.json_key_gog_appid: "",
                config.json_key_gog_appname: ""
            })
        elif file_subcategory == config.game_subcategory_steam:
            SetJsonValue(config.json_key_steam, {
                config.json_key_steam_appid: "",
                config.json_key_steam_branchid: "public"
            })

    # Set other platform keys
    else:
        SetJsonValue(config.json_key_launch_name, "REPLACEME")
        SetJsonValue(config.json_key_launch_file, best_game_file)

    # Create json directory
    success = system.MakeDirectory(
        dir = system.GetFilenameDirectory(json_file_path),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Write json file
    success = system.WriteJsonFile(
        src = json_file_path,
        json_data = json_file_data,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean json file
    success = system.CleanJsonFile(
        src = json_file_path,
        sort_keys = True,
        remove_empty_values = True,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return success

# Create game json files
def CreateGameJsonFiles(
    file_category,
    file_subcategory,
    file_root,
    passphrase = None,
    verbose = False,
    exit_on_failure = False):
    for file_title in gameinfo.FindAllGameNames(file_root, file_category, file_subcategory):
        success = collection.CreateGameJsonFile(
            file_category = file_category,
            file_subcategory = file_subcategory,
            file_title = file_title,
            passphrase = passphrase,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True
