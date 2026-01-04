# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import paths
import serialization
import environment
import fileops
import gameinfo
import cryption
import stores
import strings
import jsondata
import lockerinfo

############################################################

# Determine if game json files are possible
def are_game_json_file_possible(
    game_supercategory,
    game_category = None,
    game_subcategory = None):
    return game_supercategory in [config.Supercategory.ROMS, config.Supercategory.DLC, config.Supercategory.UPDATES]

############################################################

# Read game json data
def read_game_json_data(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not are_game_json_file_possible(game_supercategory, game_category, game_subcategory):
        return None

    # Get json file path
    json_file_path = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name)
    if not paths.does_path_exist(json_file_path):
        return None

    # Read json data
    json_file_data = serialization.read_json_file(
        src = json_file_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get platform
    game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)

    # Return json data object
    json_obj = jsondata.JsonData(
        json_data = json_file_data,
        json_platform = game_platform)
    return json_obj

############################################################

# Create game json file
def create_game_json_file(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    initial_data = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not are_game_json_file_possible(game_supercategory, game_category, game_subcategory):
        return True

    # Get json file path
    json_file_path = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name)
    if paths.does_path_exist(json_file_path):
        return True

    # Get platform
    game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)

    # Build json data
    json_file_data = {}
    if isinstance(initial_data, dict):
        json_file_data = initial_data

    # Create json data object
    json_obj = jsondata.JsonData(
        json_data = json_file_data,
        json_platform = game_platform)

    # Create json directory
    success = fileops.make_directory(
        src = paths.get_filename_directory(json_file_path),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Create json directory
    success = fileops.make_directory(
        src = paths.get_filename_directory(json_file_path),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Write json file
    success = serialization.write_json_file(
        src = json_file_path,
        json_data = json_obj.get_data(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################

# Update game json file
def update_game_json_file(
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
    if not are_game_json_file_possible(game_supercategory, game_category, game_subcategory):
        return True

    # Get platform
    game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)

    # Get regular name
    game_regular_name = gameinfo.derive_regular_name_from_game_name(game_name)

    # Get json file path
    json_file_path = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name)
    if not paths.does_path_exist(json_file_path):
        return False

    # Read json data
    json_file_data = serialization.read_json_file(
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
    all_files = paths.build_file_list(game_root)
    if locker_info:
        all_files = cryption.get_real_file_paths(
            src = all_files,
            passphrase = locker_info.get_passphrase(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Get rebased files
    rebased_files = paths.convert_file_list_to_relative_paths(all_files, game_root) if game_root else []

    # Build path lists
    all_main = []
    all_dlc = []
    all_updates = []
    all_extras = []
    all_dependencies = []
    for rebased_file in rebased_files:
        if game_supercategory in [config.Supercategory.ROMS]:
            rebased_subfile = paths.get_filename_front_slice(rebased_file)
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
    top_level_paths = paths.convert_to_top_level_paths(rebased_files)

    # Get best game file
    best_game_file = None
    if game_supercategory in [config.Supercategory.ROMS]:
        best_game_file = gameinfo.find_best_game_file(top_level_paths)
        best_game_file = paths.get_filename_file(best_game_file)

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
        store_obj = stores.get_store_by_platform(
            store_platform = game_platform,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Set computer keys
        if game_category == config.Category.COMPUTER:
            if store_obj:
                json_obj.fill_value(store_obj.get_key(), {})
                if game_platform in config.manual_import_platforms:
                    json_obj.fill_subvalue(store_obj.get_key(), config.json_key_store_appid, strings.generate_unique_id())
                    json_obj.fill_subvalue(store_obj.get_key(), config.json_key_store_appname, strings.get_slug_string(game_regular_name))
                    json_obj.fill_subvalue(store_obj.get_key(), config.json_key_store_name, game_regular_name)

        # Set other platform keys
        else:
            if isinstance(best_game_file, str) and len(best_game_file) > 0:
                json_obj.fill_value(config.json_key_launch_file, best_game_file)

        # Get latest jsondata
        latest_jsondata = None
        if store_obj:
            latest_jsondata = store_obj.get_latest_jsondata(
                identifier = json_obj.get_subvalue(store_obj.get_key(), store_obj.get_info_identifier_key()),
                branch = json_obj.get_subvalue(store_obj.get_key(), config.json_key_store_branchid),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Merge current data
        if latest_jsondata:
            for store_subdata_key in config.json_keys_store_subdata:
                if latest_jsondata.has_key(store_subdata_key):
                    if store_subdata_key == config.json_key_store_buildid:
                        existing_buildid = json_obj.get_subvalue(store_obj.get_key(), config.json_key_store_buildid)
                        new_buildid = latest_jsondata.get_value(store_subdata_key)
                        if existing_buildid and existing_buildid != config.default_buildid and new_buildid == config.default_buildid:
                            continue
                    json_obj.fill_subvalue(store_obj.get_key(), store_subdata_key, latest_jsondata.get_value(store_subdata_key))
                    if store_subdata_key == config.json_key_store_paths:
                        store_paths = json_obj.get_subvalue(store_obj.get_key(), store_subdata_key, [])
                        store_paths = paths.prune_child_paths(store_paths)
                        json_obj.set_subvalue(store_obj.get_key(), store_subdata_key, store_paths)

    # Write json file
    success = serialization.write_json_file(
        src = json_file_path,
        json_data = json_obj.get_data(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean json file
    success = serialization.clean_json_file(
        src = json_file_path,
        sort_keys = True,
        remove_empty_values = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################

# Build game json file
def build_game_json_file(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    game_root = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game root
    if not paths.is_path_directory(game_root):
        game_root = environment.get_locker_gaming_files_dir(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            locker_type = locker_type)
    if not paths.is_path_directory(game_root):
        return False

    # Log categories
    logger.log_info("Building json [Category: '%s', Subcategory: '%s', Name: '%s'] ..." %
        (game_category, game_subcategory, game_name))

    # Create json file
    success = create_game_json_file(
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
    success = update_game_json_file(
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
def build_all_game_json_files(
    locker_type = None,
    categories = None,
    subcategories = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    selected_categories = config.Category.from_list(categories) if categories else config.Category.members()
    selected_subcategories = config.Subcategory.from_list(subcategories) if subcategories else None
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in selected_categories:
            category_subcategories = config.subcategory_map[game_category]
            if selected_subcategories:
                category_subcategories = [sc for sc in category_subcategories if sc in selected_subcategories]
            for game_subcategory in category_subcategories:
                game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)
                game_names = gameinfo.find_locker_game_names(
                    game_supercategory,
                    game_category,
                    game_subcategory,
                    locker_type)
                for game_name in game_names:
                    success = build_game_json_file(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        locker_type = locker_type,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

############################################################

# Get game json ignore entries
def get_game_json_ignore_entries(
    game_supercategory,
    game_category,
    game_subcategory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not are_game_json_file_possible(game_supercategory, game_category, game_subcategory):
        return {}

    # Get json file path
    json_file_path = environment.get_game_json_metadata_ignore_file(game_supercategory, game_category, game_subcategory)

    # Create file if necessary
    if not paths.does_path_exist(json_file_path):
        fileops.touch_file(
            src = json_file_path,
            contents = "{}",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Read json data
    json_file_data = serialization.read_json_file(
        src = json_file_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return json_file_data

# Add game json ignore entry
def add_game_json_ignore_entry(
    game_supercategory,
    game_category,
    game_subcategory,
    game_identifier,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not are_game_json_file_possible(game_supercategory, game_category, game_subcategory):
        return True

    # Get platform
    game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)

    # Get json file path
    json_file_path = environment.get_game_json_metadata_ignore_file(game_supercategory, game_category, game_subcategory)

    # Create file if necessary
    if not paths.does_path_exist(json_file_path):
        fileops.touch_file(
            src = json_file_path,
            contents = "{}",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Read json data
    json_file_data = serialization.read_json_file(
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
    serialization.write_json_file(
        src = json_file_path,
        json_data = json_obj.get_data(),
        sort_keys = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Clean json file
    success = serialization.clean_json_file(
        src = json_file_path,
        sort_keys = True,
        remove_empty_values = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################
