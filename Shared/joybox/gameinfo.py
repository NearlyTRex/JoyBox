# Imports
import os

# Local imports
from joybox import config
from joybox import validation
from joybox import environment
from joybox import metadata
from joybox import metadataentry
from joybox import paths
from joybox import serialization
from joybox import jsondata
from joybox import computer
from joybox import stores
from joybox import gui
from joybox import lockerinfo
from joybox import platform_info
from joybox import gamenaming

###########################################################

# General gameinfo class
class GameInfo:

    # Constructor
    def __init__(
        self,
        json_file = None,
        game_supercategory = None,
        game_category = None,
        game_subcategory = None,
        game_name = None,
        remote_locker_type = None,
        verbose = False,
        exit_on_failure = False):

        # Json info
        self.json_data = jsondata.JsonData()
        self.json_file = json_file
        if not paths.is_path_file(self.json_file) and game_name is not None:
            self.json_file = environment.get_game_json_metadata_file(
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                game_name = game_name)
        if not paths.is_path_file(self.json_file):
            raise FileNotFoundError("Unable to find associated json file: %s" % self.json_file)

        # Metadata info
        self.metadata_file = None

        # Game info
        self.game_supercategory = game_supercategory
        self.game_category = game_category
        self.game_subcategory = game_subcategory
        self.game_name = game_name
        self.game_platform = None

        # Parse json file
        self.parse_json_file(
            json_file = self.json_file,
            remote_locker_type = remote_locker_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Parse game json
    def parse_json_file(
        self,
        json_file,
        remote_locker_type = None,
        verbose = False,
        exit_on_failure = False):

        # Read json data
        self.json_data = jsondata.JsonData(serialization.read_json_file(
            src = json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure))

        # Save json file
        self.json_file = json_file

        # Fill basic info
        self._fill_basic_info(json_file)

        # Get locker types
        if remote_locker_type is None:
            remote_locker_type = lockerinfo.get_primary_remote_locker_type()

        # Fill cache paths, then locker paths
        self._fill_cache_paths()
        self._fill_locker_paths(remote_locker_type)

    # Set the name, categories and platform from where the JSON file sits, then the metadata
    # entry; ValueError when the categories can't be derived
    def _fill_basic_info(self, json_file):

        # Get basic info based on json location
        self.game_name = paths.get_filename_basename(json_file)
        self.game_supercategory, self.game_category, self.game_subcategory = derive_game_categories_from_file(json_file)
        if None in (self.game_supercategory, self.game_category, self.game_subcategory):
            raise ValueError("Unable to derive game categories from %s" % json_file)
        self.game_platform = gamenaming.derive_game_platform_from_categories(self.game_subcategory)
        validation.assert_is_not_none(self.game_supercategory, "game_supercategory")
        validation.assert_is_not_none(self.game_category, "game_category")
        validation.assert_is_not_none(self.game_subcategory, "game_subcategory")
        validation.assert_is_not_none(self.game_platform, "game_platform")
        validation.assert_is_not_none(self.game_name, "game_name")

        # Save metadata file
        self.metadata_file = environment.get_game_metadata_file(self.game_category, self.game_subcategory)

        # Get metadata
        metadata_obj = metadata.Metadata()
        metadata_obj.import_from_metadata_file(self.metadata_file)
        metadata_entry = metadata_obj.get_game(self.game_platform, self.game_name)

        # Set metadata
        self.set_metadata(metadata_entry)

    # Set the save, general save, local cache and remote cache directories; computer games
    # save under the Sandboxie or Wine layout for the host
    def _fill_cache_paths(self):

        # Get paths
        save_dir = environment.get_cache_gaming_save_dir(self.game_category, self.game_subcategory, self.game_name)
        if self.game_category == config.Category.COMPUTER:
            if platform_info.is_windows_platform():
                save_dir = environment.get_cache_gaming_save_dir(self.game_category, self.game_subcategory, self.game_name, config.SaveType.SANDBOXIE)
            else:
                save_dir = environment.get_cache_gaming_save_dir(self.game_category, self.game_subcategory, self.game_name, config.SaveType.WINE)
        general_save_dir = environment.get_cache_gaming_save_dir(self.game_category, self.game_subcategory, self.game_name, config.SaveType.GENERAL)
        local_cache_dir = environment.get_cache_gaming_rom_dir(
            self.game_category,
            self.game_subcategory,
            self.game_name)
        remote_cache_dir = environment.get_cache_gaming_install_dir(
            self.game_category,
            self.game_subcategory,
            self.game_name)

        # Set paths
        self.set_value(config.JSON_KEY_SAVE_DIR, save_dir)
        self.set_value(config.JSON_KEY_GENERAL_SAVE_DIR, general_save_dir)
        self.set_value(config.JSON_KEY_LOCAL_CACHE_DIR, local_cache_dir)
        self.set_value(config.JSON_KEY_REMOTE_CACHE_DIR, remote_cache_dir)

    # Set the local and remote locker rom and save directories
    def _fill_locker_paths(self, remote_locker_type):

        # Get paths
        local_rom_dir = environment.get_locker_gaming_files_dir(
            self.game_supercategory,
            self.game_category,
            self.game_subcategory,
            self.game_name,
            config.LockerType.LOCAL)
        remote_rom_dir = environment.get_locker_gaming_files_dir(
            self.game_supercategory,
            self.game_category,
            self.game_subcategory,
            self.game_name,
            remote_locker_type)
        local_save_dir = environment.get_locker_gaming_save_dir(
            self.game_category,
            self.game_subcategory,
            self.game_name,
            config.LockerType.LOCAL)
        remote_save_dir = environment.get_locker_gaming_save_dir(
            self.game_category,
            self.game_subcategory,
            self.game_name,
            remote_locker_type)

        # Set paths
        self.set_value(config.JSON_KEY_LOCAL_ROM_DIR, local_rom_dir)
        self.set_value(config.JSON_KEY_REMOTE_ROM_DIR, remote_rom_dir)
        self.set_value(config.JSON_KEY_LOCAL_SAVE_DIR, local_save_dir)
        self.set_value(config.JSON_KEY_REMOTE_SAVE_DIR, remote_save_dir)

    # Path of the game's JSON metadata file this info was read from
    def get_json_file(self):
        return self.json_file

    # The in-memory JsonData wrapper, including the derived paths and metadata entry
    def get_json_data(self):
        return self.json_data

    # The game's JSON file as it is on disk, as a plain dict, without the derived values
    def read_raw_json_data(
        self,
        verbose = False,
        exit_on_failure = False):
        return serialization.read_json_file(
            src = self.get_json_file(),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Overwrite the game's JSON file with the dict given, keys sorted
    def write_raw_json_data(
        self,
        json_data,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return serialization.write_json_file(
            src = self.get_json_file(),
            json_data = json_data,
            sort_keys = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # The game's JSON file as it is on disk, wrapped in JsonData for the game's platform
    def read_wrapped_json_data(
        self,
        verbose = False,
        exit_on_failure = False):
        return jsondata.JsonData(
            json_data = self.read_raw_json_data(
                verbose = verbose,
                exit_on_failure = exit_on_failure),
            json_platform = self.get_platform())

    # Overwrite the game's JSON file with a JsonData wrapper's data
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

    # Copy the non-empty persistent keys from memory into the JSON file on disk, leaving its
    # other keys as they are
    def update_json_file(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        json_wrapper = self.read_wrapped_json_data(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        for key in config.persistent_json_keys:
            value = self.get_value(key)
            if value:
                json_wrapper.set_value(key, value)
        return self.write_wrapped_json_data(
            json_wrapper = json_wrapper,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ##############################

    # Check if key exists
    def has_key(self, key):
        return self.json_data.has_key(key)

    # Check if subkey exists
    def has_subkey(self, key, subkey):
        return self.json_data.has_subkey(key, subkey)

    # A top-level key of the in-memory JSON data, or default_value when absent
    def get_value(self, key, default_value = None):
        return self.json_data.get_value(key, default_value)

    # Get sub-value
    def get_subvalue(self, key, subkey, default_value = None):
        return self.json_data.get_subvalue(key, subkey, default_value)

    # A top-level key of the in-memory JSON data wrapped in JsonData, for nested lookups
    def get_wrapped_value(self, key, default_value = None):
        return jsondata.JsonData(self.get_value(key, default_value))

    # Get wrapped sub-value
    def get_wrapped_subvalue(self, key, subkey, default_value = None):
        return jsondata.JsonData(self.get_subvalue(key, subkey, default_value))

    # Store a top-level key in memory only; update_json_file writes it out
    def set_value(self, key, value):
        return self.json_data.set_value(key, value)

    # Set sub-value
    def set_subvalue(self, key, subkey, value):
        return self.json_data.set_subvalue(key, subkey, value)

    # Store a top-level key only when it is absent; False when it already exists
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

    # Path of the Pegasus metadata file listing this game's category and subcategory
    def get_metadata_file(self):
        return self.metadata_file

    # Check if metadata exists
    def has_metadata(self):
        return isinstance(self.get_value(config.JSON_KEY_METADATA), metadataentry.MetadataEntry)

    # The game's MetadataEntry from the Pegasus file; None when it has none
    def get_metadata(self):
        if self.has_metadata():
            return self.get_value(config.JSON_KEY_METADATA)
        return None

    # Attach a MetadataEntry in memory; write_metadata saves it to the Pegasus file
    def set_metadata(self, metadata_value):
        return self.set_value(config.JSON_KEY_METADATA, metadata_value)

    # One field of the game's Pegasus metadata entry; None when it has no entry
    def get_metadata_value(self, key):
        if self.has_metadata():
            return self.get_metadata().get_value(key)
        return None

    # Change one field of the game's metadata entry in memory; False when it has no entry
    def set_metadata_value(self, key, value):
        if self.has_metadata():
            return self.get_metadata().set_value(key, value)
        return False

    # Save the game's metadata entry back into its Pegasus metadata file; does nothing without one
    def write_metadata(self):
        if self.has_metadata():
            metadata_obj = metadata.Metadata()
            metadata_obj.import_from_metadata_file(self.metadata_file)
            metadata_obj.set_game(self.get_platform(), self.get_name(), self.get_metadata())
            metadata_obj.export_to_metadata_file(self.metadata_file)

    ##############################

    # Check if valid
    def is_valid(self):
        has_metadata = self.has_metadata()
        return has_metadata

    ##############################

    # Game name, taken from the JSON file's base name
    def get_name(self):
        return self.game_name

    # Supercategory derived from where the JSON file sits, such as Roms
    def get_supercategory(self):
        return self.game_supercategory

    # Category derived from where the JSON file sits, such as Nintendo
    def get_category(self):
        return self.game_category

    # Subcategory derived from where the JSON file sits, naming the system
    def get_subcategory(self):
        return self.game_subcategory

    # Platform matched from the subcategory
    def get_platform(self):
        return self.game_platform

    ##############################

    # Check if coop
    def is_coop(self):
        return self.get_metadata_value(config.METADATA_KEY_COOP) == "Yes"

    # Check if playable
    def is_playable(self):
        return self.get_metadata_value(config.METADATA_KEY_PLAYABLE) == "Yes"

    ##############################

    # Locker path the game's asset of the given type belongs at, whether or not it exists
    def get_asset_file(self, asset_type):
        return environment.get_locker_gaming_asset_file(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = asset_type)

    # Locker path the game's background image belongs at, whether or not it exists
    def get_background_asset(self):
        return self.get_asset_file(config.AssetType.BACKGROUND)

    # Locker path the game's back cover image belongs at, whether or not it exists
    def get_boxback_asset(self):
        return self.get_asset_file(config.AssetType.BOXBACK)

    # Locker path the game's front cover image belongs at, whether or not it exists
    def get_boxfront_asset(self):
        return self.get_asset_file(config.AssetType.BOXFRONT)

    # Locker path the game's disc or cartridge label image belongs at, whether or not it exists
    def get_label_asset(self):
        return self.get_asset_file(config.AssetType.LABEL)

    # Locker path the game's screenshot belongs at, whether or not it exists
    def get_screenshot_asset(self):
        return self.get_asset_file(config.AssetType.SCREENSHOT)

    # Locker path the game's preview video belongs at, whether or not it exists
    def get_video_asset(self):
        return self.get_asset_file(config.AssetType.VIDEO)

    ##############################

    # The JSON's launch name; None when unset
    def get_launch_name(self):
        return self.get_value(config.JSON_KEY_LAUNCH_NAME)

    # The JSON's file to launch the game from; None when unset
    def get_launch_file(self):
        return self.get_value(config.JSON_KEY_LAUNCH_FILE)

    # The JSON's directory to launch the game in; None when unset
    def get_launch_dir(self):
        return self.get_value(config.JSON_KEY_LAUNCH_DIR)

    # The JSON's source file to transform into a launchable one; None when unset
    def get_transform_file(self):
        return self.get_value(config.JSON_KEY_TRANSFORM_FILE)

    # The JSON's decryption key file for the game; None when unset
    def get_key_file(self):
        return self.get_value(config.JSON_KEY_KEY_FILE)

    # The JSON's game files, narrowed case-insensitively to one extension or any of a list;
    # empty when there are none
    def get_files(self, extension = None):
        files = self.get_value(config.JSON_KEY_FILES)
        if not files:
            return []
        if isinstance(extension, str):
            return [file for file in files if file.lower().endswith(extension.lower())]
        if isinstance(extension, (list, tuple)):
            return [file for file in files if any(file.lower().endswith(ext.lower()) for ext in extension)]
        return files

    # The JSON's DLC files; None when unset
    def get_dlc(self):
        return self.get_value(config.JSON_KEY_DLC)

    # The JSON's update files; None when unset
    def get_updates(self):
        return self.get_value(config.JSON_KEY_UPDATE)

    # The JSON's extra files, such as manuals; None when unset
    def get_extras(self):
        return self.get_value(config.JSON_KEY_EXTRA)

    # The JSON's dependencies the game needs installed; None when unset
    def get_dependencies(self):
        return self.get_value(config.JSON_KEY_DEPENDENCIES)

    ##############################

    # Cache folder for the game's saves, the Sandboxie or Wine one for computer games
    def get_save_dir(self):
        return self.get_value(config.JSON_KEY_SAVE_DIR)

    # Cache folder for the game's general saves, apart from sandbox-specific ones
    def get_general_save_dir(self):
        return self.get_value(config.JSON_KEY_GENERAL_SAVE_DIR)

    # Cache folder holding a working copy of the game's ROM files
    def get_local_cache_dir(self):
        return self.get_value(config.JSON_KEY_LOCAL_CACHE_DIR)

    # Cache folder the game installs into
    def get_remote_cache_dir(self):
        return self.get_value(config.JSON_KEY_REMOTE_CACHE_DIR)

    # Folder of the game's files in the local locker
    def get_local_rom_dir(self):
        return self.get_value(config.JSON_KEY_LOCAL_ROM_DIR)

    # Folder of the game's files in the remote locker, the primary one unless another was given
    def get_remote_rom_dir(self):
        return self.get_value(config.JSON_KEY_REMOTE_ROM_DIR)

    # Folder of the game's saves in the local locker
    def get_local_save_dir(self):
        return self.get_value(config.JSON_KEY_LOCAL_SAVE_DIR)

    # Folder of the game's saves in the remote locker
    def get_remote_save_dir(self):
        return self.get_value(config.JSON_KEY_REMOTE_SAVE_DIR)

    # Get rom dir by locker type
    def get_rom_dir(self, locker_type):
        if locker_type == config.LockerType.LOCAL:
            return self.get_local_rom_dir()
        return self.get_remote_rom_dir()

    ##############################

    # JSON key of the store that sells the game's platform; None when no store does
    def get_main_store_key(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return store_obj.get_key()
        return None

    # Type of the store that sells the game's platform; None when no store does
    def get_main_store_type(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return store_obj.get_type()
        return None

    # Where the platform's store installs games, from the settings; None when no store does
    def get_main_store_install_dir(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return store_obj.get_install_dir()
        return None

    ##############################

    # The store value identifying the game when fetching its store info; None without a store
    def get_store_info_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_info_identifier_key())
        return None

    # The store value identifying the game when installing it; None without a store
    def get_store_install_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_install_identifier_key())
        return None

    # The store value identifying the game when launching it; None without a store
    def get_store_launch_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_launch_identifier_key())
        return None

    # The store value identifying the game when downloading it; None without a store
    def get_store_download_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_download_identifier_key())
        return None

    # The store value identifying the game when looking up its artwork; None without a store
    def get_store_asset_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_asset_identifier_key())
        return None

    # The store value identifying the game when collecting its metadata; None without a store
    def get_store_metadata_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_metadata_identifier_key())
        return None

    # The store value identifying the game in its store page url; None without a store
    def get_store_page_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_page_identifier_key())
        return None

    ##############################

    # The store's app id for the game, under the given store key or the platform's own store
    def get_store_appid(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_APPID)
    # Store the app id under the given store key or the platform's own store, in memory only
    def set_store_appid(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_APPID, value)

    # The store's internal app name for the game, under the given or platform store key
    def get_store_appname(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_APPNAME)
    # Store the internal app name under the given or platform store key, in memory only
    def set_store_appname(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_APPNAME, value)

    # The game's store page link, under the given or platform store key
    def get_store_appurl(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_APPURL)
    # Store the store page link under the given or platform store key, in memory only
    def set_store_appurl(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_APPURL, value)

    # The store build branch the game tracks, under the given or platform store key
    def get_store_branchid(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_BRANCHID)
    # Store the build branch under the given or platform store key, in memory only
    def set_store_branchid(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_BRANCHID, value)

    # When the store's current build of the game was published, under the given or platform store key
    def get_store_builddate(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_BUILDDATE)
    # Store the build publish date under the given or platform store key, in memory only
    def set_store_builddate(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_BUILDDATE, value)

    # The store's identifier for the game's current build, under the given or platform store key
    def get_store_buildid(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_BUILDID)
    # Store the current build identifier under the given or platform store key, in memory only
    def set_store_buildid(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_BUILDID, value)

    # The game's title as the store lists it, under the given or platform store key
    def get_store_name(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_NAME)
    # Store the store's title for the game under the given or platform store key, in memory only
    def set_store_name(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_NAME, value)

    # The controller support level the store reports, under the given or platform store key
    def get_store_controller_support(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_CONTROLLER_SUPPORT)
    # Store the reported controller support under the given or platform store key, in memory only
    def set_store_controller_support(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_CONTROLLER_SUPPORT, value)

    # The folder name the store installs the game under, under the given or platform store key
    def get_store_installdir(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_INSTALLDIR)
    # Store the install folder name under the given or platform store key, in memory only
    def set_store_installdir(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_INSTALLDIR, value)

    # Paths the game keeps data in, such as saves, under the store key; empty when unset
    def get_store_paths(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_PATHS, [])
    # Store the game's data paths under the given or platform store key, in memory only
    def set_store_paths(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_PATHS, value)

    # Product keys recorded for the game under the store key; empty when unset
    def get_store_keys(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_KEYS, [])
    # Store the product keys under the given or platform store key, in memory only
    def set_store_keys(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_KEYS, value)

    # Raw launch program entries under the store key; empty when unset
    def get_store_launch(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_LAUNCH, [])
    # The launch entries under the store key as computer.Program objects
    def get_store_launch_programs(self, store_key = None):
        return [computer.Program(p) for p in self.get_store_launch(store_key)]
    # Store raw launch program entries under the given or platform store key, in memory only
    def set_store_launch(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_LAUNCH, value)
    # Store computer.Program objects as the launch entries, in memory only
    def set_store_launch_programs(self, value, store_key = None):
        self.set_store_launch([v.get_data() for v in value], store_key)

    # The setup section under the store key, holding preinstall, install and postinstall; empty when unset
    def get_store_setup(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_SETUP, {})
    # Store the setup section under the given or platform store key, in memory only
    def set_store_setup(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_SETUP, value)

    # Raw installer program entries from the store setup section; empty when unset
    def get_store_setup_install(self, store_key = None):
        return self.get_store_setup(store_key).get(config.JSON_KEY_STORE_SETUP_INSTALL, [])
    # The setup section's installers as computer.Program objects
    def get_store_setup_install_programs(self, store_key = None):
        return [computer.Program(p) for p in self.get_store_setup_install(store_key)]

    # Raw steps to run before installing, from the store setup section; empty when unset
    def get_store_setup_preinstall(self, store_key = None):
        return self.get_store_setup(store_key).get(config.JSON_KEY_STORE_SETUP_PREINSTALL, [])
    # The setup section's preinstall steps as computer.ProgramStep objects
    def get_store_setup_preinstall_steps(self, store_key = None):
        return [computer.ProgramStep(p) for p in self.get_store_setup_preinstall(store_key)]

    # Raw steps to run after installing, from the store setup section; empty when unset
    def get_store_setup_postinstall(self, store_key = None):
        return self.get_store_setup(store_key).get(config.JSON_KEY_STORE_SETUP_POSTINSTALL, [])
    # The setup section's postinstall steps as computer.ProgramStep objects
    def get_store_setup_postinstall_steps(self, store_key = None):
        return [computer.ProgramStep(p) for p in self.get_store_setup_postinstall(store_key)]

    ##############################

    # The Program to run: the only one, or the user's pick from a window; with none recorded,
    # scan base_dir for likely executables and save them to the JSON file; None when none are found
    def select_store_launch_program(self, base_dir, store_key = None):

        # Get list of launch programs from the json
        launch_programs = self.get_store_launch_programs(store_key) or []

        # No existing entries: scan the install and try to record these for later
        if len(launch_programs) == 0:
            launch_programs.extend(scan_launch_programs(base_dir))
            self.set_store_launch_programs(launch_programs, store_key)
            self.update_json_file()

        # Check that we have something to run
        if len(launch_programs) == 0:
            gui.display_error_popup(
                title_text = "No runnable files",
                message_text = "Computer install has no runnable files")
            return None

        # If we have exactly one choice, use that
        if len(launch_programs) == 1:
            return launch_programs[0]
        return _choose_launch_program(launch_programs)

    # Launch and installer programs under the store key whose store_subkey flag is set
    def find_store_matching_programs(self, store_key = None, store_subkey = None):
        potential_programs = []
        potential_programs += self.get_store_launch_programs(store_key)
        potential_programs += self.get_store_setup_install_programs(store_key)
        matching_programs = []
        for program in potential_programs:
            if program.get_value(store_subkey, False):
                matching_programs.append(program)
        return matching_programs

    # Determine if store has dos programs
    def does_store_have_dos_programs(self, store_key = None):
        matching_programs = self.find_store_matching_programs(store_key = store_key, store_subkey = config.PROGRAM_KEY_IS_DOS)
        return len(matching_programs) > 0

    # Determine if store has win31 programs
    def does_store_have_win31_programs(self, store_key = None):
        matching_programs = self.find_store_matching_programs(store_key = store_key, store_subkey = config.PROGRAM_KEY_IS_WIN31)
        return len(matching_programs) > 0

    # Determine if store has scumm programs
    def does_store_have_scumm_programs(self, store_key = None):
        matching_programs = self.find_store_matching_programs(store_key = store_key, store_subkey = config.PROGRAM_KEY_IS_SCUMM)
        return len(matching_programs) > 0

    # Determine if store has windows programs
    def does_store_have_windows_programs(self, store_key = None):
        if self.does_store_have_dos_programs(store_key):
            return False
        if self.does_store_have_win31_programs(store_key):
            return False
        if self.does_store_have_scumm_programs(store_key):
            return False
        return True

    # Determine if store needs to keep discs
    def does_store_need_to_keep_discs(self, store_key = None):
        if self.does_store_have_dos_programs(store_key):
            return True
        if self.does_store_have_win31_programs(store_key):
            return True
        return False

###########################################################

# Programs for the runnable files under base_dir likely to be games, skipping the ignored
# install paths
def scan_launch_programs(base_dir):

    # Get the complete list of runnable files from the install
    runnable_files_all = paths.build_file_list_by_extensions(
        root = base_dir,
        extensions = config.WindowsProgramFileType.cvalues(),
        use_relative_paths = True,
        follow_symlink_dirs = True)

    # Parse down the complete list to the ones most likely to be games
    runnable_files_likely = []
    for relative_path in runnable_files_all:
        path_to_add = paths.normalize_file_path(relative_path, separator = config.OS_PATHSEP)
        if any(path_to_add.startswith(ignore_path) for ignore_path in config.ignored_paths_install):
            continue
        runnable_files_likely.append(path_to_add)

    # Build launch programs
    launch_programs = []
    for runnable_file_likely in runnable_files_likely:
        runnable_program = computer.Program()
        runnable_program.set_exe(paths.get_filename_file(runnable_file_likely))
        runnable_program.set_cwd(paths.get_filename_directory(runnable_file_likely))
        launch_programs.append(runnable_program)
    return launch_programs

# The launch program the user picks from a choices window; None when nothing is picked
def _choose_launch_program(launch_programs):

    # Get launch info
    def get_launch_info(game_exe):
        for candidate in launch_programs:
            if paths.join_paths(candidate.get_cwd(), candidate.get_exe()) == game_exe:
                return candidate
        return None

    # Create launch program
    launch_program = None

    # Handle game selection
    def handle_game_selection(selected_file):
        nonlocal launch_program
        launch_program = get_launch_info(selected_file)

    # Build runnable choices list
    runnable_choices = []
    for candidate in launch_programs:
        runnable_choices.append(paths.join_paths(candidate.get_cwd(), candidate.get_exe()))

    # Display list of runnable files and let user decide which to run
    gui.display_choices_window(
        choice_list = runnable_choices,
        title_text = "Select Program",
        message_text = "Select program to run",
        button_text = "Run program",
        run_func = handle_game_selection)

    # Return launch info
    return launch_program

# (supercategory, category, subcategory) from where a file sits under the locker, cache or
# JSON metadata gaming roots; category falls back to Other; all None when the path doesn't fit
def derive_game_categories_from_file(game_file):

    # Check file
    if not paths.is_path_valid(game_file):
        return (None, None, None)

    # Get source directory and basename
    source_dir = paths.get_filename_directory(paths.normalize_file_path(game_file))

    # Get possible root dirs
    root_dirs = [
        paths.normalize_file_path(environment.get_locker_gaming_root_dir()),
        paths.normalize_file_path(environment.get_cache_gaming_root_dir()),
        paths.normalize_file_path(environment.get_game_json_metadata_root_dir())
    ]

    # Get relative source directory
    relative_source_dir = source_dir
    for root_dir in root_dirs:
        relative_source_dir = paths.rebase_file_path(relative_source_dir, root_dir, "")

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
    derived_subcategory = config.Subcategory.from_string(relative_file_path_tokens[1])
    derived_category = derive_game_category_from_path(relative_file_path)
    return (derived_supercategory, derived_category, derived_subcategory)

# The Computer, Microsoft, Nintendo or Sony category the relative path starts with, else Other
def derive_game_category_from_path(relative_file_path):
    for category in (config.Category.COMPUTER, config.Category.MICROSOFT, config.Category.NINTENDO, config.Category.SONY):
        if relative_file_path.startswith(category.val()):
            return category
    return config.Category.OTHER
