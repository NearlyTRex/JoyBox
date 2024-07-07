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

# General gameinfo class
class GameInfo:

    # Constructor
    def __init__(self, json_file, verbose = False, exit_on_failure = False):
        self.parse_json_file(json_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Parse game json
    def parse_json_file(self, json_file, verbose = False, exit_on_failure = False):

        # Read json data
        self.json_data = system.ReadJsonFile(json_file, verbose = verbose, exit_on_failure = exit_on_failure)

        ##############################
        # Upcast keys
        ##############################

        # Upcast list keys if they are strings
        for key in config.json_keys_list_keys:
            self.upcast_str_to_list(key)

        ##############################
        # Fill basic info
        ##############################

        # Get basic info based on json location
        json_directory = system.GetFilenameDirectory(json_file)
        json_base_name = system.GetFilenameBasename(json_file)
        json_supercategory, json_category, json_subcategory = DeriveGameCategoriesFromFile(json_file)
        json_platform = DeriveGamePlatformFromCategories(json_category, json_subcategory)
        system.AssertIsNotNone(json_supercategory, "json_supercategory")
        system.AssertIsNotNone(json_category, "json_category")
        system.AssertIsNotNone(json_subcategory, "json_subcategory")
        system.AssertIsNotNone(json_platform, "json_platform")

        # Get metadata
        metadata_file = environment.GetMetadataFile(json_category, json_subcategory)
        metadata_obj = metadata.Metadata()
        metadata_obj.import_from_metadata_file(metadata_file)
        metadata_entry = metadata_obj.get_game(json_platform, json_base_name)

        # Set metadata
        self.set_value(config.json_key_metadata, metadata_entry)

        ##############################
        # Fill default info
        ##############################

        # Fill json keys defaults
        for key in config.json_keys_list_keys:
            self.set_default_value(key, [])
        for key in config.json_keys_dict_keys:
            self.set_default_value(key, {})
        for key in config.json_keys_bool_keys:
            self.set_default_value(key, False)
        for key in config.json_keys_str_keys:
            self.set_default_value(key, None)

        # Fill sub-value defaults
        self.set_default_subvalue(config.json_key_sandbox, config.json_key_sandbox_sandboxie, {})
        self.set_default_subvalue(config.json_key_sandbox, config.json_key_sandbox_wine, {})
        self.set_default_subvalue(config.json_key_steps, config.json_key_steps_preinstall, [])
        self.set_default_subvalue(config.json_key_steps, config.json_key_steps_postinstall, [])
        self.set_default_subvalue(config.json_key_sync, config.json_key_sync_search, "")
        self.set_default_subvalue(config.json_key_sync, config.json_key_sync_data, [])
        self.set_default_subvalue(config.json_key_registry, config.json_key_registry_setup_keys, [])
        self.set_default_subvalue(config.json_key_registry, config.json_key_registry_game_keys, [])
        self.set_default_subvalue(config.json_key_steam, config.json_key_steam_appid, "")
        self.set_default_subvalue(config.json_key_steam, config.json_key_steam_branchid, "")
        self.set_default_subvalue(config.json_key_steam, config.json_key_steam_buildid, "")
        self.set_default_subvalue(config.json_key_steam, config.json_key_steam_builddate, "")
        self.set_default_subvalue(config.json_key_gog, config.json_key_gog_appid, "")
        self.set_default_subvalue(config.json_key_gog, config.json_key_gog_appname, "")
        self.set_default_subvalue(config.json_key_gog, config.json_key_gog_name, "")
        self.set_default_subvalue(config.json_key_gog, config.json_key_gog_buildid, "")

        ##############################
        # Fill path info
        ##############################

        # Get paths
        save_dir = environment.GetCachedSaveDir(json_category, json_subcategory, json_base_name)
        if json_category == config.game_category_computer:
            if environment.IsWindowsPlatform():
                save_dir = environment.GetCachedSaveDir(json_category, json_subcategory, json_base_name, config.save_type_sandboxie)
            else:
                save_dir = environment.GetCachedSaveDir(json_category, json_subcategory, json_base_name, config.save_type_wine)
        general_save_dir = environment.GetCachedSaveDir(json_category, json_subcategory, json_base_name, config.save_type_general)
        local_cache_dir = environment.GetCachedRomDir(json_category, json_subcategory, json_base_name)
        remote_cache_dir = environment.GetInstallRomDir(json_category, json_subcategory, json_base_name)

        # Set paths
        self.set_value(config.json_key_save_dir, save_dir)
        self.set_value(config.json_key_general_save_dir, general_save_dir)
        self.set_value(config.json_key_local_cache_dir, local_cache_dir)
        self.set_value(config.json_key_remote_cache_dir, remote_cache_dir)

        ##############################
        # Fill source info
        ##############################

        # Get launch/transform info
        json_launch_name = self.get_value(config.json_key_launch_name)
        json_launch_file = self.get_value(config.json_key_launch_file)
        json_transform_file = self.get_value(config.json_key_transform_file)

        # Get source dir
        source_dir = environment.GetLockerGamingRomDir(json_category, json_subcategory, json_base_name)

        # Get source file
        # In order of preference:
        # - Use launch file
        # - Use transform file
        # - Use launch name
        source_file = ""
        if isinstance(json_launch_file, list) and len(json_launch_file) == 1:
            source_file = os.path.join(source_dir, json_launch_file[0])
        if isinstance(json_transform_file, list) and len(json_transform_file) == 1:
            source_file = os.path.join(source_dir, json_transform_file[0])
        if isinstance(json_launch_name, str) and len(source_file) == 0:
            source_file = os.path.join(source_dir, json_launch_name)

        # Set source info
        self.set_value(config.json_key_source_file, source_file)
        self.set_value(config.json_key_source_dir, source_dir)

    ##############################

    # Check if key exists
    def has_key(self, key):
        return key in self.json_data

    # Check if subkey exists
    def has_subkey(self, key, subkey):
        if key in self.json_data:
            return subkey in self.json_data[key]
        return False

    # Get value
    def get_value(self, key):
        if key in self.json_data:
            return self.json_data[key]
        return None

    # Get sub-value
    def get_subvalue(self, key, subkey):
        if key in self.json_data:
            if subkey in self.json_data[key]:
                return self.json_data[key][subkey]
        return None

    # Set value
    def set_value(self, key, value):
        self.json_data[key] = value

    # Set default value
    def set_default_value(self, key, value):
        if key not in self.json_data:
            self.json_data[key] = value

    # Set default sub-value
    def set_default_subvalue(self, key, subkey, value):
        if key in self.json_data and subkey not in self.json_data[key]:
            self.json_data[key][subkey] = value

    # Get metadata value
    def get_metadata_value(self, key):
        if self.json_data[config.json_key_metadata].is_key_set(key):
            return self.json_data[config.json_key_metadata].get_value(key)
        return None

    # Upcast string to list
    def upcast_str_to_list(self, key):
        if key in self.json_data and isinstance(self.json_data[key], str):
            if self.json_data[key]:
                self.json_data[key] = [self.json_data[key]]
            else:
                self.json_data[key] = []

    ##############################

    # Get name
    def get_name(self):
        return self.get_metadata_value(config.metadata_key_game)

    # Get supercategory
    def get_supercategory(self):
        return self.get_metadata_value(config.metadata_key_supercategory)

    # Get category
    def get_category(self):
        return self.get_metadata_value(config.metadata_key_category)

    # Get subcategory
    def get_subcategory(self):
        return self.get_metadata_value(config.metadata_key_subcategory)

    # Get platform
    def get_platform(self):
        return self.get_metadata_value(config.metadata_key_platform)

    # Check if coop
    def is_coop(self):
        return self.get_metadata_value(config.metadata_key_coop) == "Yes"

    # Check if playable
    def is_playable(self):
        return self.get_metadata_value(config.metadata_key_playable) == "Yes"

    ##############################

    # Get background asset
    def get_background_asset(self):
        return environment.GetLockerGamingAssetFile(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.asset_type_background)

    # Get boxback asset
    def get_boxback_asset(self):
        return environment.GetLockerGamingAssetFile(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.asset_type_boxback)

    # Get boxfront asset
    def get_boxfront_asset(self):
        return environment.GetLockerGamingAssetFile(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.asset_type_boxfront)

    # Get label asset
    def get_label_asset(self):
        return environment.GetLockerGamingAssetFile(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.asset_type_label)

    # Get screenshot asset
    def get_screenshot_asset(self):
        return environment.GetLockerGamingAssetFile(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.asset_type_screenshot)

    # Get video asset
    def get_video_asset(self):
        return environment.GetLockerGamingAssetFile(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.asset_type_video)

    ##############################

    # Get launch name
    def get_launch_name(self):
        return self.get_value(config.json_key_launch_name)

    # Get launch file
    def get_launch_file(self):
        return self.get_value(config.json_key_launch_file)

    # Get launch dir
    def get_launch_dir(self):
        return self.get_value(config.json_key_launch_dir)

    # Get transform file
    def get_transform_file(self):
        return self.get_value(config.json_key_transform_file)

    # Get source file
    def get_source_file(self):
        return self.get_value(config.json_key_source_file)

    # Get source dir
    def get_source_dir(self):
        return self.get_value(config.json_key_source_dir)

    # Get save dir
    def get_save_dir(self):
        return self.get_value(config.json_key_save_dir)

    # Get general save dir
    def get_general_save_dir(self):
        return self.get_value(config.json_key_general_save_dir)

    # Get local cache dir
    def get_local_cache_dir(self):
        return self.get_value(config.json_key_local_cache_dir)

    # Get remote cache dir
    def get_remote_cache_dir(self):
        return self.get_value(config.json_key_remote_cache_dir)

    ##############################

    # Get files
    def get_files(self):
        return self.get_value(config.json_key_files)

    # Get dlc
    def get_dlc(self):
        return self.get_value(config.json_key_dlc)

    # Get updates
    def get_updates(self):
        return self.get_value(config.json_key_update)

    # Get extras
    def get_extras(self):
        return self.get_value(config.json_key_extra)

    # Get dependencies
    def get_dependencies(self):
        return self.get_value(config.json_key_dependencies)

    ##############################

    # Get installer exe
    def get_installer_exe(self):
        return self.get_value(config.json_key_installer_exe)

    # Get installer dos exe
    def get_installer_dos_exe(self):
        return self.get_value(config.json_key_installer_dos_exe)

    # Get installer type
    def get_installer_type(self):
        return self.get_value(config.json_key_installer_type)

    # Get disc type
    def get_disc_type(self):
        return self.get_value(config.json_key_disc_type)

    ##############################

    # Get wine setup
    def get_wine_setup(self):
        return self.get_subvalue(config.json_key_sandbox, config.json_key_sandbox_wine)

    # Get sandboxie setup
    def get_sandboxie_setup(self):
        return self.get_subvalue(config.json_key_sandbox, config.json_key_sandbox_sandboxie)

    ##############################

    # Get preinstall steps
    def get_preinstall_steps(self):
        return self.get_subvalue(config.json_key_steps, config.json_key_steps_preinstall)

    # Get postinstall steps
    def get_postinstall_steps(self):
        return self.get_subvalue(config.json_key_steps, config.json_key_steps_postinstall)

    ##############################

    # Get sync search
    def get_sync_search(self):
        return self.get_subvalue(config.json_key_sync, config.json_key_sync_search)

    # Get sync data
    def get_sync_data(self):
        return self.get_subvalue(config.json_key_sync, config.json_key_sync_data)

    ##############################

    # Get setup registry keys
    def get_setup_registry_keys(self):
        return self.get_subvalue(config.json_key_registry, config.json_key_registry_setup_keys)

    # Get game registry keys
    def get_game_registry_keys(self):
        return self.get_subvalue(config.json_key_registry, config.json_key_registry_game_keys)

    ##############################

    # Get steam appid
    def get_steam_appid(self):
        return self.get_subvalue(config.json_key_steam, config.json_key_steam_appid)

    # Get steam branchid
    def get_steam_branchid(self):
        return self.get_subvalue(config.json_key_steam, config.json_key_steam_branchid)

    # Get steam buildid
    def get_steam_buildid(self):
        return self.get_subvalue(config.json_key_steam, config.json_key_steam_buildid)

    # Get steam builddate
    def get_steam_builddate(self):
        return self.get_subvalue(config.json_key_steam, config.json_key_steam_builddate)

    ##############################

    # Get gog appid
    def get_gog_appid(self):
        return self.get_subvalue(config.json_key_gog, config.json_key_gog_appid)

    # Get gog appname
    def get_gog_appname(self):
        return self.get_subvalue(config.json_key_gog, config.json_key_gog_appname)

    # Get gog name
    def get_gog_name(self):
        return self.get_subvalue(config.json_key_gog, config.json_key_gog_name)

    # Get gog buildid
    def get_gog_buildid(self):
        return self.get_subvalue(config.json_key_gog, config.json_key_gog_buildid)

    ##############################

    # Get windows version
    def get_winver(self):
        return self.get_value(config.json_key_winver)

    # Check if 32bit
    def is_32_bit(self):
        return self.get_value(config.json_key_is_32_bit)

    # Check if dos
    def is_dos(self):
        return self.get_value(config.json_key_is_dos)

    # Check if windows 3.1
    def is_win31(self):
        return self.get_value(config.json_key_is_win31)

    # Check if scumm
    def is_scumm(self):
        return self.get_value(config.json_key_is_scumm)

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

# Derive game letter from name
def DeriveGameLetterFromName(game_name):
    letter = ""
    if len(game_name):
        letter = game_name[0].upper()
    if letter.isnumeric():
        letter = config.general_numeric_folder
    return letter

# Derive game name path from name
def DeriveGameNamePathFromName(game_name, game_platform):
    if platforms.IsLetterPlatform(game_platform):
        return os.path.join(DeriveGameLetterFromName(game_name), game_name)
    else:
        return game_name

# Derive game asset path from name
def DeriveGameAssetPathFromName(game_name, asset_type):
    return "%s/%s%s" % (asset_type, game_name, config.asset_type_extensions[asset_type])

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

# Derive game platform from categories
def DeriveGamePlatformFromCategories(game_category, game_subcategory):
    game_platform = game_subcategory
    if game_category == config.game_category_computer:
        game_platform = game_category + " - " + game_subcategory
    return game_platform

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
        system.NormalizeFilePath(environment.GetLockerGamingRootDir()),
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

###########################################################
