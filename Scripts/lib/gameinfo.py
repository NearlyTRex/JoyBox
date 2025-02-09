# Imports
import os, os.path
import sys
import re
import string

# Local imports
import config
import system
import environment
import metadata
import metadataentry
import platforms
import jsondata
import stores

###########################################################

# General gameinfo class
class GameInfo:

    # Constructor
    def __init__(
        self,
        json_file,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Json info
        self.json_data = {}
        self.json_file = None

        # Metadata info
        self.metadata_file = None

        # Game info
        self.game_supercategory = None
        self.game_category = None
        self.game_subcategory = None
        self.game_name = None
        self.game_platform = None

        # Parse json file
        self.parse_json_file(
            json_file = json_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Parse game json
    def parse_json_file(
        self,
        json_file,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Read json data
        self.json_data = system.ReadJsonFile(
            src = json_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Save json file
        self.json_file = json_file

        ##############################
        # Fill basic info
        ##############################

        # Get basic info based on json location
        self.game_name = system.GetFilenameBasename(json_file)
        self.game_supercategory, self.game_category, self.game_subcategory = DeriveGameCategoriesFromFile(json_file)
        self.game_platform = DeriveGamePlatformFromCategories(self.game_category, self.game_subcategory)
        system.AssertIsNotNone(self.game_supercategory, "game_supercategory")
        system.AssertIsNotNone(self.game_category, "game_category")
        system.AssertIsNotNone(self.game_subcategory, "game_subcategory")
        system.AssertIsNotNone(self.game_platform, "game_platform")
        system.AssertIsNotNone(self.game_name, "game_name")

        # Save metadata file
        self.metadata_file = environment.GetMetadataFile(self.game_category, self.game_subcategory)

        # Get metadata
        metadata_obj = metadata.Metadata()
        metadata_obj.import_from_metadata_file(self.metadata_file)
        metadata_entry = metadata_obj.get_game(self.game_platform, self.game_name)

        # Set metadata
        self.set_metadata(metadata_entry)

        ##############################
        # Fill default info
        ##############################

        # Fill json keys defaults
        for entry in config.json_key_defaults:
            entry_key = entry["key"]
            entry_default = entry["default"]
            if isinstance(entry_key, str):
                self.set_default_value(entry_key, entry_default)
            elif isinstance(entry_key, tuple) or isinstance(entry_key, list):
                if len(entry_key) == 2:
                    self.set_default_subvalue(entry_key[0], entry_key[1], entry_default)

        ##############################
        # Fill path info
        ##############################

        # Get paths
        save_dir = environment.GetCacheGamingSaveDir(self.game_category, self.game_subcategory, self.game_name)
        if self.game_category == config.Category.COMPUTER:
            if environment.IsWindowsPlatform():
                save_dir = environment.GetCacheGamingSaveDir(self.game_category, self.game_subcategory, self.game_name, config.SaveType.SANDBOXIE)
            else:
                save_dir = environment.GetCacheGamingSaveDir(self.game_category, self.game_subcategory, self.game_name, config.SaveType.WINE)
        general_save_dir = environment.GetCacheGamingSaveDir(self.game_category, self.game_subcategory, self.game_name, config.SaveType.GENERAL)
        local_cache_dir = environment.GetCacheGamingRomDir(self.game_category, self.game_subcategory, self.game_name)
        remote_cache_dir = environment.GetCacheGamingInstallDir(self.game_category, self.game_subcategory, self.game_name)
        local_rom_dir = environment.GetLockerGamingFilesDir(
            self.game_supercategory,
            self.game_category,
            self.game_subcategory,
            self.game_name,
            config.SourceType.LOCAL)
        remote_rom_dir = environment.GetLockerGamingFilesDir(
            self.game_supercategory,
            self.game_category,
            self.game_subcategory,
            self.game_name,
            config.SourceType.REMOTE)

        # Set paths
        self.set_value(config.json_key_save_dir, save_dir)
        self.set_value(config.json_key_general_save_dir, general_save_dir)
        self.set_value(config.json_key_local_cache_dir, local_cache_dir)
        self.set_value(config.json_key_remote_cache_dir, remote_cache_dir)
        self.set_value(config.json_key_local_rom_dir, local_rom_dir)
        self.set_value(config.json_key_remote_rom_dir, remote_rom_dir)

    # Get json file
    def get_json_file(self):
        return self.json_file

    # Get json data
    def get_json_data(self):
        return self.json_data

    # Read raw json data
    def read_raw_json_data(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return system.ReadJsonFile(
            src = self.get_json_file(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Write raw json data
    def write_raw_json_data(
        self,
        json_data,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return system.WriteJsonFile(
            src = self.get_json_file(),
            json_data = json_data,
            sort_keys = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Read wrapped json data
    def read_wrapped_json_data(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return jsondata.JsonData(
            json_data = self.read_raw_json_data(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure),
            json_platform = self.get_platform())

    # Write wrapped json data
    def write_wrapped_json_data(
        self,
        json_wrapper,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return self.write_raw_json_data(
            json_data = json_wrapper.get_data(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ##############################

    # Check if key exists
    def has_key(self, key):
        try:
            return key in self.json_data
        except:
            return False

    # Check if subkey exists
    def has_subkey(self, key, subkey):
        try:
            return subkey in self.json_data[key]
        except:
            return False

    # Get value
    def get_value(self, key, default_value = None):
        try:
            return self.json_data[key]
        except:
            return default_value

    # Get sub-value
    def get_subvalue(self, key, subkey, default_value = None):
        try:
            return self.json_data[key][subkey]
        except:
            return default_value

    # Get wrapped value
    def get_wrapped_value(self, key, default_value = None):
        try:
            return jsondata.JsonData(self.json_data[key])
        except:
            return default_value

    # Get wrapped sub-value
    def get_wrapped_subvalue(self, key, subkey, default_value = None):
        try:
            return jsondata.JsonData(self.json_data[key][subkey])
        except:
            return default_value

    # Set value
    def set_value(self, key, value):
        try:
            self.json_data[key] = value
            return True
        except:
            return False

    # Set sub-value
    def set_subvalue(self, key, subkey, value):
        try:
            self.json_data[key][subkey] = value
            return True
        except:
            return False

    # Set default value
    def set_default_value(self, key, value):
        if not self.has_key(key):
            return self.set_value(key, value)
        return False

    # Set default sub-value
    def set_default_subvalue(self, key, subkey, value):
        if self.has_key(key) and not self.has_subkey(key, subkey):
            return self.set_subvalue(key, subkey, value)
        return False

    ##############################

    # Get metadata file
    def get_metadata_file(self):
        return self.metadata_file

    # Check if metadata exists
    def has_metadata(self):
        if self.has_key(config.json_key_metadata):
            return isinstance(self.get_value(config.json_key_metadata), metadataentry.MetadataEntry)
        return False

    # Get metadata
    def get_metadata(self):
        if self.has_metadata():
            return self.get_value(config.json_key_metadata)
        return None

    # Set metadata
    def set_metadata(self, metadata):
        return self.set_value(config.json_key_metadata, metadata)

    # Get metadata value
    def get_metadata_value(self, key):
        if self.has_metadata():
            return self.get_metadata().get_value(key)
        return None

    # Set metadata value
    def set_metadata_value(self, key, value):
        if self.has_metadata():
            return self.get_metadata().set_value(key, value)
        return False

    # Write metadata
    def write_metadata(self):
        if self.has_metadata():
            metadata_obj = metadata.Metadata()
            metadata_obj.import_from_metadata_file(self.metadata_file)
            metadata_obj.set_game(self.get_platform(), self.get_name(), self.get_metadata())
            metadata_obj.export_to_metadata_file(self.metadata_file)

    ##############################

    # Upcast string to list
    def upcast_str_to_list(self, key):
        if key in self.json_data and isinstance(self.json_data[key], str):
            if self.json_data[key]:
                self.json_data[key] = [self.json_data[key]]
            else:
                self.json_data[key] = []

    ##############################

    # Check if valid
    def is_valid(self):
        has_metadata = self.has_metadata()
        return has_metadata

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
            asset_type = config.AssetType.BACKGROUND)

    # Get boxback asset
    def get_boxback_asset(self):
        return environment.GetLockerGamingAssetFile(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.AssetType.BOXBACK)

    # Get boxfront asset
    def get_boxfront_asset(self):
        return environment.GetLockerGamingAssetFile(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.AssetType.BOXFRONT)

    # Get label asset
    def get_label_asset(self):
        return environment.GetLockerGamingAssetFile(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.AssetType.LABEL)

    # Get screenshot asset
    def get_screenshot_asset(self):
        return environment.GetLockerGamingAssetFile(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.AssetType.SCREENSHOT)

    # Get video asset
    def get_video_asset(self):
        return environment.GetLockerGamingAssetFile(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.AssetType.VIDEO)

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

    # Get key file
    def get_key_file(self):
        return self.get_value(config.json_key_key_file)

    # Get files
    def get_files(self, extension = None):
        files = self.get_value(config.json_key_files)
        if not files:
            return []
        if isinstance(extension, str):
            return [file for file in files if file.lower().endswith(extension.lower())]
        elif isinstance(extension, (list, tuple)):
            return [file for file in files if any(file.lower().endswith(ext.lower()) for ext in extension)]
        return files

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

    # Get local rom dir
    def get_local_rom_dir(self):
        return self.get_value(config.json_key_local_rom_dir)

    # Get remote rom dir
    def get_remote_rom_dir(self):
        return self.get_value(config.json_key_remote_rom_dir)

    # Get rom dir
    def get_rom_dir(self, source_type):
        if source_type == config.SourceType.LOCAL:
            return self.get_local_rom_dir()
        elif source_type == config.SourceType.REMOTE:
            return self.get_remote_rom_dir()
        return None

    ##############################

    # Get main store key
    def get_main_store_key(self):
        store_obj = stores.GetStoreByPlatform(self.get_platform())
        if store_obj:
            return store_obj.GetKey()
        return None

    # Get main store type
    def get_main_store_type(self):
        store_obj = stores.GetStoreByPlatform(self.get_platform())
        if store_obj:
            return store_obj.GetType()
        return None

    # Get main store install dir
    def get_main_store_install_dir(self):
        store_obj = stores.GetStoreByPlatform(self.get_platform())
        if store_obj:
            return store_obj.GetInstallDir()
        return None

    ##############################

    # Get store appid
    def get_store_appid(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_appid)
    def set_store_appid(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_appid, value)

    # Get store appname
    def get_store_appname(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_appname)
    def set_store_appname(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_appname, value)

    # Get store appurl
    def get_store_appurl(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_appurl)
    def set_store_appurl(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_appurl, value)

    # Get store branchid
    def get_store_branchid(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_branchid)
    def set_store_branchid(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_branchid, value)

    # Get store builddate
    def get_store_builddate(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_builddate)
    def set_store_builddate(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_builddate, value)

    # Get store buildid
    def get_store_buildid(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_buildid)
    def set_store_buildid(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_buildid, value)

    # Get store name
    def get_store_name(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_name)
    def set_store_name(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_name, value)

    # Get store controller support
    def get_store_controller_support(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_controller_support)
    def set_store_controller_support(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_controller_support, value)

    # Get store installdir
    def get_store_installdir(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_installdir)
    def set_store_installdir(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_installdir, value)

    # Get store paths
    def get_store_paths(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_paths)
    def set_store_paths(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_paths, value)

    # Get store keys
    def get_store_keys(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_keys)
    def set_store_keys(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_keys, value)

    # Get store launch
    def get_store_launch(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_launch)
    def set_store_launch(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_launch, value)

    # Get store setup
    def get_store_setup(self, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if not store_key:
            return None
        return self.get_subvalue(store_key, config.json_key_store_setup)
    def set_store_setup(self, value, store_key = None):
        if not store_key:
            store_key = self.get_main_store_key()
        if store_key:
            self.set_subvalue(store_key, config.json_key_store_setup, value)

    # Get store setup install
    def get_store_setup_install(self, store_key = None):
        store_setup = self.get_store_setup(store_key)
        if not store_setup:
            return []
        if config.json_key_store_setup_install in store_setup:
            return store_setup[config.json_key_store_setup_install]
        return []

    # Get store setup preinstall
    def get_store_setup_preinstall(self, store_key = None):
        store_setup = self.get_store_setup(store_key)
        if not store_setup:
            return []
        if config.json_key_store_setup_preinstall in store_setup:
            return store_setup[config.json_key_store_setup_preinstall]
        return []

    # Get store setup postinstall
    def get_store_setup_postinstall(self, store_key = None):
        store_setup = self.get_store_setup(store_key)
        if not store_setup:
            return []
        if config.json_key_store_setup_postinstall in store_setup:
            return store_setup[config.json_key_store_setup_postinstall]
        return []

    # Find store setup matching installers
    def find_store_setup_matching_installers(self, store_key = None, store_subkey = None):
        store_setup = self.get_store_setup(store_key)
        if not store_setup or config.json_key_store_setup_install not in store_setup:
            return []
        matching_installers = []
        for setup_install in store_setup[config.json_key_store_setup_install]:
            if store_subkey and store_subkey in setup_install:
                matching_installers.append(setup_install)
        return matching_installers

    # Determine if store setup has dos installers
    def does_store_setup_have_dos_installers(self, store_key = None):
        matching_installers = self.find_store_setup_matching_installers(store_subkey = config.program_key_is_dos)
        return len(matching_installers) > 0

    # Determine if store setup has win31 installers
    def does_store_setup_have_win31_installers(self, store_key = None):
        matching_installers = self.find_store_setup_matching_installers(store_subkey = config.program_key_is_win31)
        return len(matching_installers) > 0

    # Determine if store setup has scumm installers
    def does_store_setup_have_scumm_installers(self, store_key = None):
        matching_installers = self.find_store_setup_matching_installers(store_subkey = config.program_key_is_scumm)
        return len(matching_installers) > 0

    # Determine if store setup has windows installers
    def does_store_setup_have_windows_installers(self, store_key = None):
        if self.does_store_setup_have_dos_installers():
            return False
        if self.does_store_setup_have_win31_installers():
            return False
        if self.does_store_setup_have_scumm_installers():
            return False
        return True

###########################################################

# Find best suited game file
def FindBestGameFile(game_files):

    # Collect game file entries
    game_file_entries = []
    if isinstance(game_files, list):
        for file in game_files:
            game_file_entry = {}
            game_file_entry["file"] = os.path.abspath(file)
            game_file_entry["weight"] = config.gametype_weight_else
            for key in config.gametype_weights.keys():
                if file.endswith(key):
                    game_file_entry["weight"] = config.gametype_weights[key]
                    break
            game_file_entries.append(game_file_entry)

    # Use this to get the best file
    game_file = ""
    for game_file_entry in sorted(game_file_entries, key=lambda d: d["weight"]):
        game_file = game_file_entry["file"]
        break
    return game_file

# Find all game names
def FindAllGameNames(base_dir, game_supercategory, game_category, game_subcategory):

    # Get base path
    base_path = system.JoinPaths(base_dir, game_supercategory, game_category, game_subcategory)

    # Get platform
    game_platform = DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Collect game names
    game_names = []
    if platforms.IsLetterPlatform(game_platform):
        for game_letter in system.GetDirectoryContents(base_path):
            for game_name in system.GetDirectoryContents(system.JoinPaths(base_path, game_letter)):
                game_names.append(game_name)
    else:
        for game_name in system.GetDirectoryContents(base_path):
            game_names.append(game_name)
    return game_names

# Find json game names
def FindJsonGameNames(game_supercategory, game_category, game_subcategory):
    base_dir = environment.GetJsonMetadataRootDir()
    return FindAllGameNames(base_dir, game_supercategory, game_category, game_subcategory)

# Find locker game names
def FindLockerGameNames(game_supercategory, game_category, game_subcategory, source_type = None):
    base_dir = environment.GetLockerGamingRootDir(source_type)
    return FindAllGameNames(base_dir, game_supercategory, game_category, game_subcategory)

###########################################################

# Derive regular name from game name
def DeriveRegularNameFromGameName(game_name, custom_prefix = "", custom_suffix = ""):
    regular_name = game_name
    for flippable_word in config.flippable_words:
        segment_before = f", {flippable_word} "
        segment_after = f"{flippable_word} "
        if segment_before in regular_name:
            regular_name = regular_name.replace(segment_before, " ")
            regular_name = segment_after + regular_name
    regular_name = re.sub(r"\((.*?)\)", "", regular_name).strip()
    regular_name = f"{custom_prefix}{regular_name}{custom_suffix}"
    return regular_name

# Derive game name from regular name
def DeriveGameNameFromRegularName(regular_name, region="USA"):
    game_name = regular_name.strip()
    game_name = game_name.replace(":", " -")
    game_name = game_name.replace("&", "and")
    game_name = re.sub(r"-?\s*CE$", " Collector's Edition", game_name)
    game_name = system.CleanRichText(game_name)
    game_name = system.CapitalizeText(game_name)
    game_name = system.ReplaceInvalidPathCharacters(game_name)
    for flippable_word in config.flippable_words:
        if game_name.startswith(f"{flippable_word} "):
            base_name = game_name[len(flippable_word) + 1:]
            if " - " in base_name:
                parts = base_name.split(" - ", 1)
                if len(parts) == 2:
                    first_part = parts[0].strip()
                    second_part = parts[1].strip()
                    game_name = f"{first_part}, {flippable_word} - {second_part}"
                else:
                    game_name = f"{base_name}, {flippable_word}"
            else:
                game_name = f"{base_name}, {flippable_word}"
            break
    return f"{game_name} ({region})"

# Derive slug name from regular name
def DeriveSlugNameFromRegularName(regular_name):
    return system.GetSlugString(regular_name)

# Derive slug name from game name
def DeriveSlugNameFromGameName(game_name, custom_prefix = "", custom_suffix = ""):
    regular_name = DeriveRegularNameFromGameName(game_name, custom_prefix, custom_suffix)
    return DeriveSlugNameFromRegularName(regular_name)

# Derive game letter from name
def DeriveGameLetterFromName(game_name):
    letter = ""
    if len(game_name):
        letter = game_name[0].upper()
    if letter.isnumeric():
        letter = config.general_folder_numeric
    return letter

# Derive game search terms from name
def DeriveGameSearchTermsFromName(game_name, game_platform, custom_prefix = "", custom_suffix = ""):
    regular_name = DeriveRegularNameFromGameName(game_name, custom_prefix, custom_suffix)
    return system.EncodeUrlString(regular_name, use_plus = True)

# Derive game name path from name
def DeriveGameNamePathFromName(game_name, game_platform):
    if platforms.IsLetterPlatform(game_platform):
        return system.JoinPaths(DeriveGameLetterFromName(game_name), game_name)
    else:
        return game_name

# Derive game asset path from name
def DeriveGameAssetPathFromName(game_name, asset_type):
    return "%s/%s%s" % (asset_type.val(), game_name, asset_type.cval())

# Derive game categories from platform
def DeriveGameCategoriesFromPlatform(game_platform):
    if not game_platform:
        return (None, None, None)
    derived_supercategory = config.Supercategory.ROMS
    derived_category = None
    derived_subcategory = None
    for game_category in config.Category.members():
        if game_platform.name.startswith(game_category.name):
            derived_category = game_category
    for game_subcategory in config.Subcategory.members():
        if game_platform.name.startswith(game_subcategory.name):
            derived_subcategory = game_subcategory
    return (derived_supercategory, derived_category, derived_subcategory)

# Derive game platform from categories
def DeriveGamePlatformFromCategories(game_category, game_subcategory):
    for game_platform in config.Platform.members():
        if game_platform.val().endswith(game_subcategory.val()):
            return game_platform
    return None

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
        system.NormalizeFilePath(environment.GetCacheGamingRootDir()),
        system.NormalizeFilePath(environment.GetJsonMetadataRootDir())
    ]

    # Get relative source directory
    relative_source_dir = source_dir
    for root_dir in root_dirs:
        relative_source_dir = system.RebaseFilePath(relative_source_dir, root_dir, "")

    # Derive supercategory
    derived_supercategory = None
    for possible_supercategory in config.Supercategory.members():
        if relative_source_dir.startswith(possible_supercategory.val()):
            derived_supercategory = possible_supercategory
    if not derived_supercategory:
        return (None, None, None)

    # Get relative path
    relative_source_index = relative_source_dir.index(derived_supercategory.val()) + len(derived_supercategory.val())
    relative_file_path = relative_source_dir[relative_source_index:].strip(os.sep)
    relative_file_path_tokens = relative_file_path.split(os.sep)
    if len(relative_file_path_tokens) < 2:
        return (None, None, None)

    # Get derived category and subcategory
    derived_category = None
    derived_subcategory = config.Subcategory.from_string(relative_file_path_tokens[1])
    if relative_file_path.startswith(config.Category.COMPUTER.val()):
        derived_category = config.Category.COMPUTER
    elif relative_file_path.startswith(config.Category.MICROSOFT.val()):
        derived_category = config.Category.MICROSOFT
    elif relative_file_path.startswith(config.Category.NINTENDO.val()):
        derived_category = config.Category.NINTENDO
    elif relative_file_path.startswith(config.Category.SONY.val()):
        derived_category = config.Category.SONY
    else:
        derived_category = config.Category.OTHER
    return (derived_supercategory, derived_category, derived_subcategory)

###########################################################
