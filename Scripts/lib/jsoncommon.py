# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
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
def ParseGeneralJson(json_file, verbose = False, exit_on_failure = False):

    # Read json data
    json_data = system.ReadJsonFile(json_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Get automatic info based on json location
    json_directory = system.GetFilenameDirectory(json_file)
    json_base_name = system.GetFilenameBasename(json_file)
    json_regular_name = metadata.ConvertMetadataNameToRegularName(json_base_name)
    json_supercategory, json_category, json_subcategory = metadata.DeriveMetadataCategoriesFromFile(json_file)
    json_platform = metadata.DeriveMetadataPlatform(json_category, json_subcategory)

    # Fill gaps
    SetDefaultValue(json_data, config.general_key_base_name, json_base_name)
    SetDefaultValue(json_data, config.general_key_regular_name, json_regular_name)
    SetDefaultValue(json_data, config.general_key_supercategory, json_supercategory)
    SetDefaultValue(json_data, config.general_key_category, json_category)
    SetDefaultValue(json_data, config.general_key_subcategory, json_subcategory)
    SetDefaultValue(json_data, config.general_key_platform, json_platform)
    for key in config.json_keys_list_keys:
        SetDefaultValue(json_data, key, [])
    for key in config.json_keys_dict_keys:
        SetDefaultValue(json_data, key, {})
    for key in config.json_keys_bool_keys:
        SetDefaultValue(json_data, key, False)
    for key in config.json_keys_str_keys:
        SetDefaultValue(json_data, key, None)

    # Get potential cache source info
    potential_cache_source_name = json_data[config.general_key_launch_name]
    potential_cache_source_file = json_data[config.general_key_launch_file]
    potential_cache_transform_file = json_data[config.general_key_transform_file]

    # Derive actual cache source
    cache_source_file = ""
    cache_source_dir = environment.GetRomDir(json_category, json_subcategory, json_base_name)
    if potential_cache_source_file:
        cache_source_file = os.path.join(cache_source_dir, potential_cache_source_file)
    if potential_cache_transform_file:
        cache_source_file = os.path.join(cache_source_dir, potential_cache_transform_file)
    if potential_cache_source_name and len(source_file) == 0:
        cache_source_file = os.path.join(cache_source_dir, potential_cache_source_name)

    # Set cache source
    json_data[config.general_key_cache_source_file] = cache_source_file
    json_data[config.general_key_cache_source_dir] = cache_source_dir

    # Return json
    return json_data

# Parse computer json
def ParseComputerJson(json_file, verbose = False, exit_on_failure = False):

    # Get general json info
    json_data = ParseGeneralJson(json_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Fill gaps
    SetDefaultSubValue(json_data, config.computer_key_sandbox, config.computer_key_sandbox_sandboxie, {})
    SetDefaultSubValue(json_data, config.computer_key_sandbox, config.computer_key_sandbox_wine, {})
    SetDefaultSubValue(json_data, config.computer_key_steps, config.computer_key_steps_preinstall, [])
    SetDefaultSubValue(json_data, config.computer_key_steps, config.computer_key_steps_postinstall, [])
    SetDefaultSubValue(json_data, config.computer_key_sync, config.computer_key_sync_search, "")
    SetDefaultSubValue(json_data, config.computer_key_sync, config.computer_key_sync_data, [])
    SetDefaultSubValue(json_data, config.computer_key_registry, config.computer_key_registry_keep_setup, False)
    SetDefaultSubValue(json_data, config.computer_key_registry, config.computer_key_registry_setup_keys, [])

    # Return json
    return json_data
