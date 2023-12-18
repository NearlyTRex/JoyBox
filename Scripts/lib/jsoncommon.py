# Imports
import os, os.path
import sys

# Local imports
import config
import system
import metadata

# Set default value
def SetDefaultValue(dict_var, dict_key, default_value):
    if dict_key not in dict_var:
        dict_var[dict_key] = default_value

# Set default sub-value
def SetDefaultSubValue(dict_var, dict_key, dict_subkey, default_subvalue):
    if dict_key in dict_var and dict_subkey not in dict_var[dict_key]:
        dict_var[dict_key][dict_subkey] = default_subvalue

# Parse general json
def ParseGeneralJson(game_name, game_platform, json_file, verbose = False, exit_on_failure = False):

    # Read json data
    json_data = system.ReadJsonFile(json_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Get automatic info based on json location
    json_directory = system.GetFilenameDirectory(json_file)
    json_base_name = system.GetFilenameBasename(json_file)
    json_regular_name = metadata.ConvertMetadataNameToRegularName(json_base_name)
    json_supercategory, json_category, json_subcategory = metadata.DeriveMetadataCategoriesFromFile(json_file)
    json_platform = metadata.DeriveMetadataPlatform(json_category, json_subcategory)

    # Get json info
    json_launch_name = None
    if config.general_key_launch_name in json_data:
        json_launch_name = json_data[config.general_key_launch_name]
    json_launch_file = None
    if config.general_key_launch_file in json_data:
        json_launch_file = json_data[config.general_key_launch_file]
    json_transform_file = None
    if config.general_key_transform_file in json_data:
        json_transform_file = json_data[config.general_key_transform_file]

    # Get source info
    source_file = ""
    source_dir = environment.GetRomDir(json_category, json_subcategory, json_base_name)
    if json_launch_file:
        source_file = os.path.join(source_dir, json_launch_file)
    if json_transform_file:
        source_file = os.path.join(source_dir, json_transform_file)
    if json_launch_name and len(source_file) == 0:
        source_file = os.path.join(source_dir, json_launch_name)

    # Build game info
    game_info[config.general_key_launch_name] = json_launch_name
    game_info[config.general_key_launch_file] = json_launch_file
    game_info[config.general_key_transform_file] = json_transform_file
    game_info[config.general_key_source_file] = source_file
    game_info[config.general_key_source_dir] = source_dir
    return game_info

# Parse computer json
def ParseComputerJson(json_file, verbose = False, exit_on_failure = False):

    # Read json data
    json_data = system.ReadJsonFile(json_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Get automatic info based on json location
    json_directory = system.GetFilenameDirectory(json_file)
    json_base_name = system.GetFilenameBasename(json_file)
    json_regular_name = metadata.ConvertMetadataNameToRegularName(json_base_name)
    json_supercategory, json_category, json_subcategory = metadata.DeriveMetadataCategoriesFromFile(json_file)
    json_platform = metadata.DeriveMetadataPlatform(json_category, json_subcategory)

    # Fill gaps for general keys
    for key in config.general_keys_list_keys:
        SetDefaultValue(json_data, key, [])
    for key in config.computer_keys_list_keys:
        SetDefaultValue(json_data, key, [])
    for key in config.computer_keys_dict_keys:
        SetDefaultValue(json_data, key, {})
    for key in config.computer_keys_bool_keys:
        SetDefaultValue(json_data, key, False)
    for key in config.computer_keys_str_keys:
        SetDefaultValue(json_data, key, None)

    # Fill gaps for special dictionaries
    SetDefaultSubValue(json_data, config.computer_key_sandbox, config.computer_key_sandbox_sandboxie, {})
    SetDefaultSubValue(json_data, config.computer_key_sandbox, config.computer_key_sandbox_wine, {})
    SetDefaultSubValue(json_data, config.computer_key_steps, config.computer_key_steps_preinstall, [])
    SetDefaultSubValue(json_data, config.computer_key_steps, config.computer_key_steps_postinstall, [])
    SetDefaultSubValue(json_data, config.computer_key_sync, config.computer_key_sync_search, "")
    SetDefaultSubValue(json_data, config.computer_key_sync, config.computer_key_sync_data, [])
    SetDefaultSubValue(json_data, config.computer_key_registry, config.computer_key_registry_keep_setup, False)
    SetDefaultSubValue(json_data, config.computer_key_registry, config.computer_key_registry_setup_keys, [])

    # Fill gaps for derived json data
    SetDefaultValue(json_data, config.computer_key_source_dir, json_directory)
    SetDefaultValue(json_data, config.computer_key_source_file, json_file)
    SetDefaultValue(json_data, config.computer_key_base_name, json_base_name)
    SetDefaultValue(json_data, config.computer_key_regular_name, json_regular_name)
    SetDefaultValue(json_data, config.computer_key_supercategory, json_supercategory)
    SetDefaultValue(json_data, config.computer_key_category, json_category)
    SetDefaultValue(json_data, config.computer_key_subcategory, json_subcategory)
    SetDefaultValue(json_data, config.computer_key_platform, json_platform)

    # Convert some string fields to list
    for key in config.computer_keys_list_keys:
        if isinstance(json_data[key], str):
            json_data[key] = [json_data[key]]

    # Return json
    return json_data
