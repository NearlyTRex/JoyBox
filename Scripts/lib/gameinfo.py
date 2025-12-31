# Imports
import os, os.path
import sys
import re
import string

# Local imports
import config
import system
import text
import validation
import logger
import environment
import metadata
import metadataentry
import paths
import platforms
import serialization
import jsondata
import computer
import stores
import strings
import gui
import lockerinfo

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
        pretend_run = False,
        exit_on_failure = False):

        # Json info
        self.json_data = jsondata.JsonData()
        self.json_file = json_file
        if not paths.is_path_file(self.json_file):
            self.json_file = environment.get_game_json_metadata_file(
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                game_name = game_name)
        if not paths.is_path_file(self.json_file):
            raise Exception("Unable to find associated json file")

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
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Parse game json
    def parse_json_file(
        self,
        json_file,
        remote_locker_type = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Read json data
        self.json_data = jsondata.JsonData(serialization.read_json_file(
            src = json_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure))

        # Save json file
        self.json_file = json_file

        ##############################
        # Fill basic info
        ##############################

        # Get basic info based on json location
        self.game_name = paths.get_filename_basename(json_file)
        self.game_supercategory, self.game_category, self.game_subcategory = derive_game_categories_from_file(json_file)
        self.game_platform = derive_game_platform_from_categories(self.game_category, self.game_subcategory)
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

        ##############################
        # Fill path info
        ##############################

        # Get locker types
        if remote_locker_type is None:
            remote_locker_type = lockerinfo.get_primary_remote_locker_type()

        # Get paths
        save_dir = environment.get_cache_gaming_save_dir(self.game_category, self.game_subcategory, self.game_name)
        if self.game_category == config.Category.COMPUTER:
            if environment.is_windows_platform():
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
            self.game_supercategory,
            self.game_category,
            self.game_subcategory,
            self.game_name,
            config.LockerType.LOCAL)
        remote_save_dir = environment.get_locker_gaming_save_dir(
            self.game_supercategory,
            self.game_category,
            self.game_subcategory,
            self.game_name,
            remote_locker_type)

        # Set paths
        self.set_value(config.json_key_save_dir, save_dir)
        self.set_value(config.json_key_general_save_dir, general_save_dir)
        self.set_value(config.json_key_local_cache_dir, local_cache_dir)
        self.set_value(config.json_key_remote_cache_dir, remote_cache_dir)
        self.set_value(config.json_key_local_rom_dir, local_rom_dir)
        self.set_value(config.json_key_remote_rom_dir, remote_rom_dir)
        self.set_value(config.json_key_local_save_dir, local_save_dir)
        self.set_value(config.json_key_remote_save_dir, remote_save_dir)

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
        return serialization.read_json_file(
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
        return serialization.write_json_file(
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

    # Update json file
    def update_json_file(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        json_wrapper = self.read_wrapped_json_data(
            verbose = verbose,
            pretend_run = pretend_run,
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

    # Get value
    def get_value(self, key, default_value = None):
        return self.json_data.get_value(key, default_value)

    # Get sub-value
    def get_subvalue(self, key, subkey, default_value = None):
        return self.json_data.get_subvalue(key, subkey, default_value)

    # Get wrapped value
    def get_wrapped_value(self, key, default_value = None):
        return jsondata.JsonData(self.get_value(key, default_value))

    # Get wrapped sub-value
    def get_wrapped_subvalue(self, key, subkey, default_value = None):
        return jsondData.JsonData(self.get_subvalue(key, subkey, default_value))

    # Set value
    def set_value(self, key, value):
        return self.json_data.set_value(key, value)

    # Set sub-value
    def set_subvalue(self, key, subkey, value):
        return self.json_data.set_subvalue(key, subkey, value)

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

    # Check if valid
    def is_valid(self):
        has_metadata = self.has_metadata()
        return has_metadata

    ##############################

    # Get name
    def get_name(self):
        return self.game_name

    # Get supercategory
    def get_supercategory(self):
        return self.game_supercategory

    # Get category
    def get_category(self):
        return self.game_category

    # Get subcategory
    def get_subcategory(self):
        return self.game_subcategory

    # Get platform
    def get_platform(self):
        return self.game_platform

    ##############################

    # Check if coop
    def is_coop(self):
        return self.get_metadata_value(config.metadata_key_coop) == "Yes"

    # Check if playable
    def is_playable(self):
        return self.get_metadata_value(config.metadata_key_playable) == "Yes"

    ##############################

    # Get background asset
    def get_background_asset(self):
        return environment.get_locker_gaming_asset_file(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.AssetType.BACKGROUND)

    # Get boxback asset
    def get_boxback_asset(self):
        return environment.get_locker_gaming_asset_file(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.AssetType.BOXBACK)

    # Get boxfront asset
    def get_boxfront_asset(self):
        return environment.get_locker_gaming_asset_file(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.AssetType.BOXFRONT)

    # Get label asset
    def get_label_asset(self):
        return environment.get_locker_gaming_asset_file(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.AssetType.LABEL)

    # Get screenshot asset
    def get_screenshot_asset(self):
        return environment.get_locker_gaming_asset_file(
            game_category = self.get_category(),
            game_subcategory = self.get_subcategory(),
            game_name = self.get_name(),
            asset_type = config.AssetType.SCREENSHOT)

    # Get video asset
    def get_video_asset(self):
        return environment.get_locker_gaming_asset_file(
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

    # Get local save dir
    def get_local_save_dir(self):
        return self.get_value(config.json_key_local_save_dir)

    # Get remote save dir
    def get_remote_save_dir(self):
        return self.get_value(config.json_key_remote_save_dir)

    # Get rom dir by locker type
    def get_rom_dir(self, locker_type):
        if locker_type == config.LockerType.LOCAL:
            return self.get_local_rom_dir()
        else:
            return self.get_remote_rom_dir()

    ##############################

    # Get main store key
    def get_main_store_key(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return store_obj.get_key()
        return None

    # Get main store type
    def get_main_store_type(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return store_obj.get_type()
        return None

    # Get main store install dir
    def get_main_store_install_dir(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return store_obj.get_install_dir()
        return None

    ##############################

    # Get store info identifier
    def get_store_info_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_info_identifier_key())
        return None

    # Get store install identifier
    def get_store_install_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_install_identifier_key())
        return None

    # Get store launch identifier
    def get_store_launch_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_launch_identifier_key())
        return None

    # Get store download identifier
    def get_store_download_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_download_identifier_key())
        return None

    # Get store asset identifier
    def get_store_asset_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_asset_identifier_key())
        return None

    # Get store metadata identifier
    def get_store_metadata_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_metadata_identifier_key())
        return None

    # Get store page identifier
    def get_store_page_identifier(self):
        store_obj = stores.get_store_by_platform(self.get_platform())
        if store_obj:
            return self.get_subvalue(store_obj.get_key(), store_obj.get_page_identifier_key())
        return None

    ##############################

    # Get store appid
    def get_store_appid(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_appid)
    def set_store_appid(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_appid, value)

    # Get store appname
    def get_store_appname(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_appname)
    def set_store_appname(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_appname, value)

    # Get store appurl
    def get_store_appurl(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_appurl)
    def set_store_appurl(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_appurl, value)

    # Get store branchid
    def get_store_branchid(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_branchid)
    def set_store_branchid(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_branchid, value)

    # Get store builddate
    def get_store_builddate(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_builddate)
    def set_store_builddate(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_builddate, value)

    # Get store buildid
    def get_store_buildid(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_buildid)
    def set_store_buildid(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_buildid, value)

    # Get store name
    def get_store_name(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_name)
    def set_store_name(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_name, value)

    # Get store controller support
    def get_store_controller_support(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_controller_support)
    def set_store_controller_support(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_controller_support, value)

    # Get store installdir
    def get_store_installdir(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_installdir)
    def set_store_installdir(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_installdir, value)

    # Get store paths
    def get_store_paths(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_paths, [])
    def set_store_paths(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_paths, value)

    # Get store keys
    def get_store_keys(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_keys, [])
    def set_store_keys(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_keys, value)

    # Get store launch
    def get_store_launch(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_launch, [])
    def get_store_launch_programs(self, store_key = None):
        return [computer.Program(p) for p in self.get_store_launch(store_key)]
    def set_store_launch(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_launch, value)
    def set_store_launch_programs(self, value, store_key = None):
        self.set_store_launch([v.get_data() for v in value], store_key)

    # Get store setup
    def get_store_setup(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_setup, {})
    def set_store_setup(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.json_key_store_setup, value)

    # Get store setup install
    def get_store_setup_install(self, store_key = None):
        return self.get_store_setup(store_key).get(config.json_key_store_setup_install, [])
    def get_store_setup_install_programs(self, store_key = None):
        return [computer.Program(p) for p in self.get_store_setup_install(store_key)]

    # Get store setup preinstall
    def get_store_setup_preinstall(self, store_key = None):
        return self.get_store_setup(store_key).get(config.json_key_store_setup_preinstall, [])
    def get_store_setup_preinstall_steps(self, store_key = None):
        return [computer.ProgramStep(p) for p in self.get_store_setup_preinstall(store_key)]

    # Get store setup postinstall
    def get_store_setup_postinstall(self, store_key = None):
        return self.get_store_setup(store_key).get(config.json_key_store_setup_postinstall, [])
    def get_store_setup_postinstall_steps(self, store_key = None):
        return [computer.ProgramStep(p) for p in self.get_store_setup_postinstall(store_key)]

    ##############################

    # Select store launch program
    def select_store_launch_program(self, base_dir, store_key = None):

        # Get list of launch programs from the json
        launch_programs = self.get_store_launch_programs(store_key)
        if not launch_programs:
            launch_programs = []

        # No existing entries
        if len(launch_programs) == 0:

            # Get the complete list of runnable files from the install
            runnable_files_all = paths.build_file_list_by_extensions(
                root = base_dir,
                extensions = config.WindowsProgramFileType.cvalues(),
                use_relative_paths = True,
                follow_symlink_dirs = True)

            # Parse down the complete list to the ones most likely to be games
            runnable_files_likely = []
            for relative_path in runnable_files_all:
                path_to_add = paths.normalize_file_path(relative_path, separator = config.os_pathsep)
                should_ignore = False
                for ignore_path in config.ignored_paths_install:
                    if path_to_add.startswith(ignore_path):
                        should_ignore = True
                        break
                if should_ignore:
                    continue
                runnable_files_likely.append(path_to_add)

            # Add to launch programs
            for runnable_file_likely in runnable_files_likey:
                runnable_program = computer.Program()
                runnable_program.set_exe(paths.get_filename_file(runnable_file))
                runnable_program.set_cwd(paths.get_filename_directory(runnable_file))
                launch_programs.append(runnable_program)

            # Try to record these for later
            self.set_store_launch_programs(launch_programs, store_key)
            self.update_json_file()

        # Get launch info
        def get_launch_info(game_exe):
            for launch_program in launch_programs:
                launch_exe = launch_program.get_exe()
                launch_cwd = launch_program.get_cwd()
                if paths.join_paths(launch_cwd, launch_exe) in game_exe:
                    return launch_program
            return None

        # Check that we have something to run
        if len(launch_programs) == 0:
            gui.display_error_popup(
                title_text = "No runnable files",
                message_text = "Computer install has no runnable files")

        # If we have exactly one choice, use that
        if len(launch_programs) == 1:
            return launch_programs[0]

        # Create launch program
        launch_program = None

        # Handle game selection
        def handle_game_selection(selected_file):
            nonlocal launch_program
            launch_program = get_launch_info(selected_file)

        # Build runnable choices list
        runnable_choices = []
        for launch_program in launch_programs:
            launch_exe = launch_program.get_exe()
            launch_cwd = launch_program.get_cwd()
            runnable_choices.append(paths.join_paths(launch_cwd, launch_exe))

        # Display list of runnable files and let user decide which to run
        gui.display_choices_window(
            choice_list = runnable_choices,
            title_text = "Select Program",
            message_text = "Select program to run",
            button_text = "Run program",
            run_func = HandleGameSelection)

        # Return launch info
        return launch_program

    # Find store matching programs
    def find_store_matching_programs(self, store_key = None, store_subkey = None):
        potential_programs = []
        potential_programs += self.get_store_launch_programs(store_key)
        potential_programs += self.get_store_setup_install_programs(store_key)
        matching_programs = []
        for program in potential_programs:
            if program.has_subkey(store_key, store_subkey):
                matching_programs.append(program)
        return matching_programs

    # Determine if store has dos programs
    def does_store_have_dos_programs(self, store_key = None):
        matching_programs = self.find_store_matching_programs(store_key = store_key, store_subkey = config.program_key_is_dos)
        return len(matching_programs) > 0

    # Determine if store has win31 programs
    def does_store_have_win31_programs(self, store_key = None):
        matching_programs = self.find_store_matching_programs(store_key = store_key, store_subkey = config.program_key_is_win31)
        return len(matching_programs) > 0

    # Determine if store has scumm programs
    def does_store_have_scumm_programs(self, store_key = None):
        matching_programs = self.find_store_matching_programs(store_key = store_key, store_subkey = config.program_key_is_scumm)
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

# Find best suited game file
def find_best_game_file(game_files):

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
def find_all_game_names(base_dir, game_supercategory, game_category, game_subcategory):

    # Get base path
    base_path = paths.join_paths(base_dir, game_supercategory, game_category, game_subcategory)

    # Get platform
    game_platform = derive_game_platform_from_categories(game_category, game_subcategory)

    # Collect game names
    game_names = []
    if platforms.is_letter_platform(game_platform):
        for game_letter in sorted(paths.get_directory_contents(base_path)):
            for game_name in sorted(paths.get_directory_contents(paths.join_paths(base_path, game_letter))):
                game_names.append(game_name)
    else:
        for game_name in sorted(paths.get_directory_contents(base_path)):
            game_names.append(game_name)
    return game_names

# Find json game names
def find_json_game_names(game_supercategory, game_category, game_subcategory):
    base_dir = environment.get_game_json_metadata_root_dir()
    return find_all_game_names(base_dir, game_supercategory, game_category, game_subcategory)

# Find locker game names
def find_locker_game_names(game_supercategory, game_category, game_subcategory, locker_type = None, locker_base_dir = None):
    if locker_base_dir:
        base_dir = paths.join_paths(locker_base_dir, config.LockerFolderType.GAMING)
    else:
        base_dir = environment.get_locker_gaming_root_dir(locker_type)
    return find_all_game_names(base_dir, game_supercategory, game_category, game_subcategory)

###########################################################

# Derive regular name from game name
def derive_regular_name_from_game_name(game_name, custom_prefix = "", custom_suffix = ""):
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
def derive_game_name_from_regular_name(regular_name, region="USA"):
    game_name = regular_name.strip()
    game_name = game_name.replace(":", " -")
    game_name = game_name.replace("&", "and")
    game_name = re.sub(r"-?\s*CE$", " Collector's Edition", game_name)
    game_name = text.clean_rich_text(game_name)
    game_name = text.capitalize_text(game_name)
    game_name = paths.replace_invalid_path_characters(game_name)
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
def derive_slug_name_from_regular_name(regular_name):
    return strings.get_slug_string(regular_name)

# Derive slug name from game name
def derive_slug_name_from_game_name(game_name, custom_prefix = "", custom_suffix = ""):
    regular_name = derive_regular_name_from_game_name(game_name, custom_prefix, custom_suffix)
    return derive_slug_name_from_regular_name(regular_name)

# Derive game letter from name
def derive_game_letter_from_name(game_name):
    letter = ""
    if len(game_name):
        letter = game_name[0].upper()
    if letter.isnumeric():
        letter = config.general_folder_numeric
    return letter

# Derive game search terms from name
def derive_game_search_terms_from_name(game_name, game_platform, custom_prefix = "", custom_suffix = ""):
    regular_name = derive_regular_name_from_game_name(game_name, custom_prefix, custom_suffix)
    return strings.encode_url_string(regular_name, use_plus = True)

# Derive game name path from name
def derive_game_name_path_from_name(game_name, game_platform):
    if platforms.is_letter_platform(game_platform):
        return paths.join_paths(derive_game_letter_from_name(game_name), game_name)
    else:
        return game_name

# Derive game asset path from name
def derive_game_asset_path_from_name(game_name, asset_type):
    return "%s/%s%s" % (asset_type.val(), game_name, asset_type.cval())

# Derive game categories from platform
def derive_game_categories_from_platform(game_platform):
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
def derive_game_platform_from_categories(game_category, game_subcategory):
    for game_platform in config.Platform.members():
        if game_platform.val().endswith(game_subcategory.val()):
            return game_platform
    return None

# Derive game categories from file
def derive_game_categories_from_file(game_file):

    # Check file
    if not paths.is_path_valid(game_file):
        return (None, None, None)

    # Get source directory and basename
    source_dir = paths.get_filename_directory(paths.normalize_file_path(game_file))
    base_name = paths.get_filename_basename(paths.normalize_file_path(game_file))

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

# Iterate selected game categories
def iterate_selected_game_categories(
    parser,
    generation_mode = None,
    game_supercategories = None,
    game_subcategory_map = None):

    # Determine generation mode
    args, unknown = parser.parse_known_args()
    if generation_mode is None:
        generation_mode = getattr(args, "generation_mode", config.GenerationModeType.STANDARD)

    # Custom mode - yield single category tuple from explicit args
    if generation_mode == config.GenerationModeType.CUSTOM:
        if not args.game_category:
            raise ValueError("Game category is required for custom mode")
        if not args.game_subcategory:
            raise ValueError("Game subcategory is required for custom mode")
        yield (args.game_supercategory, args.game_category, args.game_subcategory)
        return

    # Standard mode - iterate filesystem
    if game_supercategories is None:
        game_supercategories = parser.get_selected_supercategories()
    if game_subcategory_map is None:
        game_subcategory_map = parser.get_selected_subcategories()
    for game_supercategory in sorted(game_supercategories):
        for game_category, game_subcategories in sorted(game_subcategory_map.items()):
            for game_subcategory in sorted(game_subcategories):
                yield (game_supercategory, game_category, game_subcategory)

###########################################################

# Iterate selected game infos
def iterate_selected_game_infos(
    parser,
    generation_mode = None,
    locker_type = None,
    locker_base_dir = None,
    game_supercategories = None,
    game_subcategory_map = None,
    game_name_filter = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Determine generation mode
    args, unknown = parser.parse_known_args()
    if generation_mode is None:
        generation_mode = getattr(args, "generation_mode", config.GenerationModeType.STANDARD)

    # Custom mode - yield single GameInfo from explicit args
    if generation_mode == config.GenerationModeType.CUSTOM:
        if not args.game_category:
            raise ValueError("Game category is required for custom mode")
        if not args.game_subcategory:
            raise ValueError("Game subcategory is required for custom mode")
        if not args.game_name:
            raise ValueError("Game name is required for custom mode")
        yield GameInfo(
            game_supercategory = args.game_supercategory,
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            game_name = args.game_name,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return

    # Standard mode - iterate filesystem
    if game_name_filter is None:
        game_name_filter = getattr(args, "game_name", None)
    for game_supercategory, game_category, game_subcategory in iterate_selected_game_categories(
        parser = parser,
        generation_mode = generation_mode,
        game_supercategories = game_supercategories,
        game_subcategory_map = game_subcategory_map):
        if locker_type is not None or locker_base_dir is not None:
            game_names = find_locker_game_names(
                game_supercategory,
                game_category,
                game_subcategory,
                locker_type,
                locker_base_dir)
        else:
            game_names = find_json_game_names(
                game_supercategory,
                game_category,
                game_subcategory)
        if game_name_filter:
            game_names = [g for g in game_names if g == game_name_filter]
        for game_name in game_names:
            try:
                yield GameInfo(
                    game_supercategory = game_supercategory,
                    game_category = game_category,
                    game_subcategory = game_subcategory,
                    game_name = game_name,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
            except Exception as e:
                logger.log_warning("Skipping '%s': %s" % (game_name, str(e)))

###########################################################
