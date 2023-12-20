# Imports
import os, os.path
import sys
import re

# Local imports
import config
import system
import environment
import metadata
import platforms

###########################################################

# Find best suited game file
def FindBestGameFile(game_directory):
    game_file_entries = []
    for obj in system.GetDirectoryContents(game_directory):
        obj_path = os.path.join(game_directory, obj)
        if os.path.isfile(obj_path):
            game_file_entry = {}
            game_file_entry["file"] = os.path.abspath(obj_path)
            game_file_entry["weight"] = config.gametype_weight_else
            for key in config.gametype_weights.keys():
                if obj.endswith(key):
                    game_file_entry["weight"] = config.gametype_weights[key]
                    break
            game_file_entries.append(game_file_entry)
    game_file = ""
    for game_file_entry in sorted(game_file_entries, key=lambda d: d["weight"]):
        game_file = game_file_entry["file"]
        break
    return game_file

# Find all game names
def FindAllGameNames(base_dir, game_category, game_subcategory):
    game_names = []
    base_path = os.path.join(base_dir, game_category, game_subcategory)
    if game_category == config.game_category_computer:
        for game_letter in system.GetDirectoryContents(base_path):
            for game_name in system.GetDirectoryContents(os.path.join(base_path, game_letter)):
                game_names.append(game_name)
    else:
        for game_name in system.GetDirectoryContents(base_path):
            game_names.append(game_name)
    return game_names

###########################################################

# Derive regular name from game name
def DeriveRegularNameFromGameName(game_name):
    regular_name = game_name
    if ", The " in regular_name:
        regular_name = regular_name.replace(", The ", " ")
        regular_name = "The " + regular_name
    if ", A " in regular_name:
        regular_name = regular_name.replace(", A ", " ")
        regular_name = "A " + regular_name
    regular_name = re.sub(r"\((.*?)\)", "", regular_name).strip()
    return regular_name

# Derive game name from path
def DeriveGameNameFromPath(game_path):
    rom_dir = system.GetFilenameDirectory(game_path)
    if not rom_dir.endswith(")"):
        return ""
    return os.path.basename(rom_dir)

# Derive game letter from name
def DeriveGameLetterFromName(game_name):
    letter = ""
    if len(game_name):
        letter = game_name[0].upper()
    if letter.isnumeric():
        letter = config.general_numeric_folder
    return letter

# Derive game categories from platform
def DeriveGameCategoriesFromPlatform(game_platform):
    if not game_platform:
        return (None, None, None)
    derived_category = ""
    derived_subcategory = ""
    if game_platform.startswith(config.game_category_computer):
        derived_category = config.game_category_computer
        derived_subcategory = game_platform.replace(config.game_category_computer + " - ", "")
    elif game_platform.startswith(config.game_category_microsoft):
        derived_category = config.game_category_microsoft
        derived_subcategory = game_platform
    elif game_platform.startswith(config.game_category_nintendo):
        derived_category = config.game_category_nintendo
        derived_subcategory = game_platform
    elif game_platform.startswith(config.game_category_sony):
        derived_category = config.game_category_sony
        derived_subcategory = game_platform
    else:
        derived_category = config.game_category_other
        derived_subcategory = game_platform
    return (config.game_supercategory_roms, derived_category, derived_subcategory)

# Derive game categories from file
def DeriveGameCategoriesFromFile(game_file):

    # Check file
    if not system.IsPathValid(game_file):
        return (None, None, None)

    # Get source directory and basename
    source_dir = system.GetFilenameDirectory(system.NormalizeFilePath(game_file))
    base_name = system.GetFilenameBasename(system.NormalizeFilePath(game_file))

    # Get possible root dirs
    root_dirs = [
        system.NormalizeFilePath(environment.GetGamingStorageRootDir()),
        system.NormalizeFilePath(environment.GetGamingLocalCacheRootDir()),
        system.NormalizeFilePath(environment.GetGamingRemoteCacheRootDir()),
        system.NormalizeFilePath(environment.GetJsonMetadataRootDir())
    ]

    # Get relative source directory
    relative_source_dir = source_dir
    for root_dir in root_dirs:
        relative_source_dir = system.RebaseFilePath(relative_source_dir, root_dir, "")

    # Derive supercategory
    derived_supercategory = ""
    for possible_supercategory in config.game_supercategories:
        if relative_source_dir.startswith(possible_supercategory):
            derived_supercategory = possible_supercategory
    if len(derived_supercategory) == 0:
        return (None, None, None)

    # Get relative path
    relative_file_path = relative_source_dir[relative_source_dir.index(derived_supercategory) + len(derived_supercategory):].strip(os.sep)
    relative_file_path_tokens = relative_file_path.split(os.sep)
    if len(relative_file_path_tokens) < 2:
        return (None, None, None)

    # Get derived category and subcategory
    derived_category = ""
    derived_subcategory = relative_file_path_tokens[1]
    if relative_file_path.startswith(config.game_category_computer):
        derived_category = config.game_category_computer
    elif relative_file_path.startswith(config.game_category_microsoft):
        derived_category = config.game_category_microsoft
    elif relative_file_path.startswith(config.game_category_nintendo):
        derived_category = config.game_category_nintendo
    elif relative_file_path.startswith(config.game_category_sony):
        derived_category = config.game_category_sony
    else:
        derived_category = config.game_category_other
    return (derived_supercategory, derived_category, derived_subcategory)

# Derive game platform from categories
def DeriveGamePlatformFromCategories(game_category, game_subcategory):
    game_platform = game_subcategory
    if game_category == config.game_category_computer:
        game_platform = game_category + " - " + game_subcategory
    return game_platform

###########################################################

# Check if game json is launchable
def IsGameJsonLaunchable(json_file):

    # Get json info
    json_data = ParseGameJson(json_file)
    json_base_name = json_data[config.json_key_base_name]
    json_category = json_data[config.json_key_category]
    json_subcategory = json_data[config.json_key_subcategory]
    json_platform = json_data[config.json_key_platform]

    # Check platform
    if platforms.HasNoLauncher(json_platform):
        return False

    # Get metadata file
    metadata_file = environment.GetMetadataFile(json_category, json_subcategory, config.metadata_format_pegasus)
    if not os.path.isfile(metadata_file):
        return False

    # Parse metadata file
    metadata_obj = metadata.Metadata()
    metadata_obj.import_from_pegasus_file(metadata_file)

    # Check metadata
    game_entry = metadata_obj.get_game(json_platform, json_base_name)
    if game_entry[config.metadata_key_playable] != "Yes":
        return False

    # Should be launchable
    return True

# Parse game json
def ParseGameJson(json_file, verbose = False, exit_on_failure = False):

    # Read json data
    json_data = system.ReadJsonFile(json_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Get automatic info based on json location
    json_directory = system.GetFilenameDirectory(json_file)
    json_base_name = system.GetFilenameBasename(json_file)
    json_regular_name = DeriveRegularNameFromGameName(json_base_name)
    json_supercategory, json_category, json_subcategory = DeriveGameCategoriesFromFile(json_file)
    json_platform = DeriveGamePlatformFromCategories(json_category, json_subcategory)

    # Set default value
    def SetDefaultValue(dict_var, dict_key, default_value):
        if dict_key not in dict_var:
            dict_var[dict_key] = default_value

    # Set default sub-value
    def SetDefaultSubValue(dict_var, dict_key, dict_subkey, default_subvalue):
        if dict_key in dict_var and dict_subkey not in dict_var[dict_key]:
            dict_var[dict_key][dict_subkey] = default_subvalue

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

###########################################################
