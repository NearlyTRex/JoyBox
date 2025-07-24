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
import lockerinfo

############################################################

# Determine if game json files are possible
def AreGameJsonFilePossible(
    game_supercategory,
    game_category = None,
    game_subcategory = None):
    return game_supercategory in [config.Supercategory.ROMS, config.Supercategory.DLC, config.Supercategory.UPDATES]

############################################################

# Read game json data
def ReadGameJsonData(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not AreGameJsonFilePossible(game_supercategory, game_category, game_subcategory):
        return None

    # Get json file path
    json_file_path = environment.GetGameJsonMetadataFile(game_supercategory, game_category, game_subcategory, game_name)
    if not system.DoesPathExist(json_file_path):
        return None

    # Read json data
    json_file_data = system.ReadJsonFile(
        src = json_file_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get platform
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Return json data object
    json_obj = jsondata.JsonData(
        json_data = json_file_data,
        json_platform = game_platform)
    return json_obj

############################################################

# Create game json file
def CreateGameJsonFile(
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
    json_file_path = environment.GetGameJsonMetadataFile(game_supercategory, game_category, game_subcategory, game_name)
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

# Update game json file
def UpdateGameJsonFile(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    game_root,
    locker_type = None,
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
    json_file_path = environment.GetGameJsonMetadataFile(game_supercategory, game_category, game_subcategory, game_name)
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

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)

    # Get all files
    all_files = system.BuildFileList(game_root)
    if locker_info:
        all_files = cryption.GetRealFilePaths(
            src = all_files,
            passphrase = locker_info.get_passphrase(),
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
        if game_supercategory in [config.Supercategory.ROMS]:
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
        else:
            all_main.append(rebased_file)

    # Get top level paths
    top_level_paths = system.ConvertToTopLevelPaths(rebased_files)

    # Get best game file
    best_game_file = None
    if game_supercategory in [config.Supercategory.ROMS]:
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

    # Rom keys
    if game_supercategory in [config.Supercategory.ROMS]:

        # Get store
        store_obj = stores.GetStoreByPlatform(
            store_platform = game_platform,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Set computer keys
        if game_category == config.Category.COMPUTER:
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

# Build game json file
def BuildGameJsonFile(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    game_root = None,
    locker_type = None,
    source_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game root
    if not system.IsPathDirectory(game_root):
        game_root = environment.GetLockerGamingFilesDir(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            source_type = source_type)
    if not system.IsPathDirectory(game_root):
        return False

    # Log categories
    system.LogInfo("Building json [Category: '%s', Subcategory: '%s', Name: '%s'] ..." %
        (game_category, game_subcategory, game_name))

    # Create json file
    success = CreateGameJsonFile(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Update json file
    success = UpdateGameJsonFile(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        game_root = game_root,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Build all game json files
def BuildAllGameJsonFiles(
    locker_type = None,
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
                    success = BuildGameJsonFile(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        locker_type = locker_type,
                        source_type = source_type,
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
    json_file_path = environment.GetGameJsonMetadataIgnoreFile(game_supercategory, game_category, game_subcategory)

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
    json_file_path = environment.GetGameJsonMetadataIgnoreFile(game_supercategory, game_category, game_subcategory)

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
