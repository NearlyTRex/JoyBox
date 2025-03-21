# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import gameinfo
import cryption
import stores
import jsondata

############################################################

# Determine if game json files are possible
def AreGameJsonFilePossible(
    game_supercategory,
    game_category = None,
    game_subcategory = None):
    return (game_supercategory == config.Supercategory.ROMS)

############################################################

# Create game json file
def CreateJsonFile(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    initial_data = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not AreGameJsonFilePossible(game_supercategory, game_category, game_subcategory):
        return True

    # Get json file path
    json_file_path = environment.GetJsonMetadataFile(game_supercategory, game_category, game_subcategory, game_name)
    if system.DoesPathExist(json_file_path):
        return True

    # Get platform
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Build json data
    json_file_data = {}
    if isinstance(initial_data, dict):
        json_file_data = initial_data

    # Create json data object
    json_obj = jsondata.JsonData(
        json_data = json_file_data,
        json_platform = game_platform)

    # Create json directory
    success = system.MakeDirectory(
        src = system.GetFilenameDirectory(json_file_path),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Create json directory
    success = system.MakeDirectory(
        src = system.GetFilenameDirectory(json_file_path),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Write json file
    success = system.WriteJsonFile(
        src = json_file_path,
        json_data = json_obj.get_data(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################

# Update json file
def UpdateJsonFile(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    game_root,
    passphrase = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not AreGameJsonFilePossible(game_supercategory, game_category, game_subcategory):
        return True

    # Get platform
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Get regular name
    game_regular_name = gameinfo.DeriveRegularNameFromGameName(game_name)

    # Get json file path
    json_file_path = environment.GetJsonMetadataFile(game_supercategory, game_category, game_subcategory, game_name)
    if not system.DoesPathExist(json_file_path):
        return False

    # Read json data
    json_file_data = system.ReadJsonFile(
        src = json_file_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Create json data object
    json_obj = jsondata.JsonData(
        json_data = json_file_data,
        json_platform = game_platform)

    # Get all files
    all_files = system.BuildFileList(game_root)
    if isinstance(passphrase, str) and len(passphrase) > 0:
        all_files = cryption.GetRealFilePaths(
            src = all_files,
            passphrase = passphrase,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Get rebased files
    rebased_files = system.ConvertFileListToRelativePaths(all_files, game_root)

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

    # Get top level paths
    top_level_paths = system.ConvertToTopLevelPaths(rebased_files)

    # Get best game file
    best_game_file = gameinfo.FindBestGameFile(top_level_paths)
    best_game_file = system.GetFilenameFile(best_game_file)

    # Set common keys
    if isinstance(rebased_files, list) and len(rebased_files) > 0:
        json_obj.fill_value(config.json_key_files, rebased_files)
    if isinstance(all_dlc, list) and len(all_dlc) > 0:
        json_obj.fill_value(config.json_key_dlc, all_dlc)
    if isinstance(all_updates, list) and len(all_updates) > 0:
        json_obj.fill_value(config.json_key_update, all_updates)
    if isinstance(all_extras, list) and len(all_extras) > 0:
        json_obj.fill_value(config.json_key_extra, all_extras)
    if isinstance(all_dependencies, list) and len(all_dependencies) > 0:
        json_obj.fill_value(config.json_key_dependencies, all_dependencies)
    if isinstance(best_game_file, str) and len(best_game_file) > 0:
        json_obj.fill_value(config.json_key_transform_file, best_game_file)

    # Set computer keys
    if game_category == config.Category.COMPUTER:
        store_obj = stores.GetStoreByPlatform(game_platform)
        if store_obj:
            json_obj.fill_value(store_obj.GetKey(), {})
            if game_platform in config.manual_import_platforms:
                json_obj.fill_subvalue(store_obj.GetKey(), config.json_key_store_appid, system.GenerateUniqueID())
                json_obj.fill_subvalue(store_obj.GetKey(), config.json_key_store_appname, system.GetSlugString(game_regular_name))
                json_obj.fill_subvalue(store_obj.GetKey(), config.json_key_store_name, game_regular_name)

    # Set other platform keys
    else:
        if isinstance(best_game_file, str) and len(best_game_file) > 0:
            json_obj.fill_value(config.json_key_launch_file, best_game_file)

    # Get store
    store_obj = stores.GetStoreByPlatform(
        store_platform = game_platform,
        login = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get latest jsondata
    latest_jsondata = None
    if store_obj:
        latest_jsondata = store_obj.GetLatestJsondata(
            identifier = json_obj.get_subvalue(store_obj.GetKey(), store_obj.GetInfoIdentifierKey()),
            branch = json_obj.get_subvalue(store_obj.GetKey(), config.json_key_store_branchid),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Merge current data
    if latest_jsondata:
        for store_subdata_key in config.json_keys_store_subdata:
            if latest_jsondata.has_key(store_subdata_key):
                json_obj.fill_subvalue(store_obj.GetKey(), store_subdata_key, latest_jsondata.get_value(store_subdata_key))
                if store_subdata_key == config.json_key_store_paths:
                    paths = json_obj.get_subvalue(store_obj.GetKey(), store_subdata_key, [])
                    paths = system.PruneChildPaths(paths)
                    json_obj.set_subvalue(store_obj.GetKey(), store_subdata_key, paths)

    # Write json file
    success = system.WriteJsonFile(
        src = json_file_path,
        json_data = json_obj.get_data(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean json file
    success = system.CleanJsonFile(
        src = json_file_path,
        sort_keys = True,
        remove_empty_values = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################

# Build game json files
def BuildGameJsonFiles(
    passphrase = None,
    source_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
                game_names = gameinfo.FindLockerGameNames(
                    game_supercategory,
                    game_category,
                    game_subcategory,
                    source_type)
                for game_name in game_names:

                    # Get scan path
                    scan_game_path = environment.GetLockerGamingFilesDir(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        source_type = source_type)

                    # Build json
                    if system.IsPathDirectory(scan_game_path):
                        system.LogInfo("Building json [Category: '%s', Subcategory: '%s', Name: '%s'] ..." %
                            (game_category, game_subcategory, game_name))
                        success = CreateJsonFile(
                            game_supercategory = game_supercategory,
                            game_category = game_category,
                            game_subcategory = game_subcategory,
                            game_name = game_name,
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = exit_on_failure)
                        if not success:
                            return False
                        success = UpdateJsonFile(
                            game_supercategory = game_supercategory,
                            game_category = game_category,
                            game_subcategory = game_subcategory,
                            game_name = game_name,
                            game_root = scan_game_path,
                            passphrase = passphrase,
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = exit_on_failure)
                        if not success:
                            return False

    # Should be successful
    return True

############################################################

# Get game json ignore entries
def GetGameJsonIgnoreEntries(
    game_supercategory,
    game_category,
    game_subcategory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not AreGameJsonFilePossible(game_supercategory, game_category, game_subcategory):
        return {}

    # Get json file path
    json_file_path = environment.GetJsonMetadataIgnoreFile(game_supercategory, game_category, game_subcategory)

    # Create file if necessary
    if not system.DoesPathExist(json_file_path):
        system.TouchFile(
            src = json_file_path,
            contents = "{}",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Read json data
    json_file_data = system.ReadJsonFile(
        src = json_file_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return json_file_data

# Add game json ignore entry
def AddGameJsonIgnoreEntry(
    game_supercategory,
    game_category,
    game_subcategory,
    game_identifier,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not AreGameJsonFilePossible(game_supercategory, game_category, game_subcategory):
        return True

    # Get platform
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Get json file path
    json_file_path = environment.GetJsonMetadataIgnoreFile(game_supercategory, game_category, game_subcategory)

    # Create file if necessary
    if not system.DoesPathExist(json_file_path):
        system.TouchFile(
            src = json_file_path,
            contents = "{}",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Read json data
    json_file_data = system.ReadJsonFile(
        src = json_file_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Create json data object
    json_obj = jsondata.JsonData(
        json_data = json_file_data,
        json_platform = game_platform)

    # Add entry
    json_obj.set_value(game_identifier, game_name)

    # Write json file
    system.WriteJsonFile(
        src = json_file_path,
        json_data = json_obj.get_data(),
        sort_keys = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Clean json file
    success = system.CleanJsonFile(
        src = json_file_path,
        sort_keys = True,
        remove_empty_values = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################
