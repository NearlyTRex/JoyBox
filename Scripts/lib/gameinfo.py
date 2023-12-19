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

# Parse game json
def ParseGameJson(json_file, verbose = False, exit_on_failure = False):

    # Read json data
    json_data = system.ReadJsonFile(json_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Get automatic info based on json location
    json_directory = system.GetFilenameDirectory(json_file)
    json_base_name = system.GetFilenameBasename(json_file)
    json_regular_name = metadata.ConvertMetadataNameToRegularName(json_base_name)
    json_supercategory, json_category, json_subcategory = metadata.DeriveMetadataCategoriesFromFile(json_file)
    json_platform = metadata.DeriveMetadataPlatform(json_category, json_subcategory)

    # Fill gaps
    SetDefaultValue(json_data, config.json_key_base_name, json_base_name)
    SetDefaultValue(json_data, config.json_key_regular_name, json_regular_name)
    SetDefaultValue(json_data, config.json_key_supercategory, json_supercategory)
    SetDefaultValue(json_data, config.json_key_category, json_category)
    SetDefaultValue(json_data, config.json_key_subcategory, json_subcategory)
    SetDefaultValue(json_data, config.json_key_platform, json_platform)
    for key in config.json_keys_list_keys:
        SetDefaultValue(json_data, key, [])
    for key in config.json_keys_dict_keys:
        SetDefaultValue(json_data, key, {})
    for key in config.json_keys_bool_keys:
        SetDefaultValue(json_data, key, False)
    for key in config.json_keys_str_keys:
        SetDefaultValue(json_data, key, None)

    # Upcast list keys if they are strings
    for key in config.json_keys_list_keys:
        if isinstance(json_data[key], str):
            if json_data[key]:
                json_data[key] = [json_data[key]]
            else:
                json_data[key] = []

    # Fill sub-value gaps
    SetDefaultSubValue(json_data, config.json_key_sandbox, config.json_key_sandbox_sandboxie, {})
    SetDefaultSubValue(json_data, config.json_key_sandbox, config.json_key_sandbox_wine, {})
    SetDefaultSubValue(json_data, config.json_key_steps, config.json_key_steps_preinstall, [])
    SetDefaultSubValue(json_data, config.json_key_steps, config.json_key_steps_postinstall, [])
    SetDefaultSubValue(json_data, config.json_key_sync, config.json_key_sync_search, "")
    SetDefaultSubValue(json_data, config.json_key_sync, config.json_key_sync_data, [])
    SetDefaultSubValue(json_data, config.json_key_registry, config.json_key_registry_keep_setup, False)
    SetDefaultSubValue(json_data, config.json_key_registry, config.json_key_registry_setup_keys, [])

    # Get launch/transform info
    json_launch_name = json_data[config.json_key_launch_name]
    json_launch_file = json_data[config.json_key_launch_file]
    json_transform_file = json_data[config.json_key_transform_file]

    # Get source info
    source_file = ""
    source_dir = environment.GetRomDir(json_category, json_subcategory, json_base_name)
    if isinstance(json_launch_file, list) and len(json_launch_file) == 1:
        source_file = os.path.join(source_dir, json_launch_file[0])
    elif isinstance(json_transform_file, list) and len(json_transform_file) == 1:
        source_file = os.path.join(source_dir, json_transform_file[0])
    if isinstance(json_launch_name, str) and len(source_file) == 0:
        source_file = os.path.join(source_dir, json_launch_name)

    # Set source info
    json_data[config.json_key_source_file] = source_file
    json_data[config.json_key_source_dir] = source_dir

    # Return json
    return json_data
