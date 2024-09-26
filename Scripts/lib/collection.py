# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import gameinfo
import platforms
import system
import metadata
import cryption
import jsondata

# Create game json file
def CreateGameJsonFile(
    file_category,
    file_subcategory,
    file_title,
    file_root = None,
    initial_data = None,
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
    if isinstance(initial_data, dict):
        json_file_data = initial_data

    # Already existing json file
    if os.path.exists(json_file_path):
        json_file_data = system.ReadJsonFile(
            src = json_file_path,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

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
    exe_main = [f for f in all_main if f.endswith(".exe") or f.endswith(".msi")]
    exe_dlc = [f for f in all_dlc if f.endswith(".exe") or f.endswith(".msi")]
    exe_updates = [f for f in all_updates if f.endswith(".exe") or f.endswith(".msi")]

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

    # Create json data object
    json_obj = jsondata.JsonData(json_file_data, file_platform)

    # Set common keys
    json_obj.FillJsonValue(config.json_key_files, rebased_files)
    json_obj.FillJsonValue(config.json_key_dlc, all_dlc)
    json_obj.FillJsonValue(config.json_key_update, all_updates)
    json_obj.FillJsonValue(config.json_key_extra, all_extras)
    json_obj.FillJsonValue(config.json_key_dependencies, all_dependencies)
    json_obj.FillJsonValue(config.json_key_transform_file, best_game_file)

    # Set computer keys
    if file_category == config.game_category_computer:
        json_obj.FillJsonValue(config.json_key_installer_exe, computer_installers)
        if file_subcategory == config.game_subcategory_amazon_games:
            json_obj.FillJsonValue(config.json_key_amazon, {
                config.json_key_store_appid: "",
                config.json_key_store_name: ""
            })
        elif file_subcategory == config.game_subcategory_epic_games:
            json_obj.FillJsonValue(config.json_key_epic, {
                config.json_key_store_appname: ""
            })
        elif file_subcategory == config.game_subcategory_gog:
            json_obj.FillJsonValue(config.json_key_gog, {
                config.json_key_store_appid: "",
                config.json_key_store_appname: ""
            })
        elif file_subcategory == config.game_subcategory_itchio:
            json_obj.FillJsonValue(config.json_key_itchio, {
                config.json_key_store_appid: "",
                config.json_key_store_appurl: "",
                config.json_key_store_name: ""
            })
        elif file_subcategory == config.game_subcategory_steam:
            json_obj.FillJsonValue(config.json_key_steam, {
                config.json_key_store_appid: "",
                config.json_key_store_branchid: "public"
            })

    # Set other platform keys
    else:
        json_obj.FillJsonValue(config.json_key_launch_name, "REPLACEME")
        json_obj.FillJsonValue(config.json_key_launch_file, best_game_file)

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
        json_data = json_obj.GetJsonData(),
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
        success = CreateGameJsonFile(
            file_category = file_category,
            file_subcategory = file_subcategory,
            file_title = file_title,
            passphrase = passphrase,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Add metadata entry
def AddMetadataEntry(
    file_category,
    file_subcategory,
    file_name,
    verbose = False,
    exit_on_failure = False):

    # Find metadata file
    metadata_file = environment.GetMetadataFile(file_category, file_subcategory)
    if not metadata_file:
        return False

    # Load metadata file
    metadata_obj = metadata.Metadata()
    metadata_obj.import_from_metadata_file(
        metadata_file = metadata_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Derive game data
    file_platform = gameinfo.DeriveGamePlatformFromCategories(file_category, file_subcategory)
    file_json_file = environment.GetJsonRomMetadataFile(file_category, file_subcategory, file_name)
    file_boxfront = gameinfo.DeriveGameAssetPathFromName(file_name, config.asset_type_boxfront)
    file_boxback = gameinfo.DeriveGameAssetPathFromName(file_name, config.asset_type_boxback)
    file_background = gameinfo.DeriveGameAssetPathFromName(file_name, config.asset_type_background)
    file_screenshot = gameinfo.DeriveGameAssetPathFromName(file_name, config.asset_type_screenshot)
    file_video = gameinfo.DeriveGameAssetPathFromName(file_name, config.asset_type_video)

    # Create new entry
    new_entry = metadata.MetadataEntry()
    new_entry.set_game(file_name)
    new_entry.set_platform(file_platform)
    new_entry.set_file(file_json_file)
    new_entry.set_boxfront(file_boxfront)
    new_entry.set_boxback(file_boxback)
    new_entry.set_background(file_background)
    new_entry.set_screenshot(file_screenshot)
    new_entry.set_players("1")
    new_entry.set_coop("No")
    new_entry.set_playable("Yes")

    # Add new entry
    metadata_obj.add_game(new_entry)

    # Write metadata file
    metadata_obj.export_to_metadata_file(
        metadata_file = metadata_file,
        append_existing = False,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return True
