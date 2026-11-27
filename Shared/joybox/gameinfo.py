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

        ##############################
        # Fill basic info
        ##############################

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

        ##############################
        # Fill path info
        ##############################

        # Get locker types
        if remote_locker_type is None:
            remote_locker_type = lockerinfo.get_primary_remote_locker_type()

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
        self.set_value(config.JSON_KEY_SAVE_DIR, save_dir)
        self.set_value(config.JSON_KEY_GENERAL_SAVE_DIR, general_save_dir)
        self.set_value(config.JSON_KEY_LOCAL_CACHE_DIR, local_cache_dir)
        self.set_value(config.JSON_KEY_REMOTE_CACHE_DIR, remote_cache_dir)
        self.set_value(config.JSON_KEY_LOCAL_ROM_DIR, local_rom_dir)
        self.set_value(config.JSON_KEY_REMOTE_ROM_DIR, remote_rom_dir)
        self.set_value(config.JSON_KEY_LOCAL_SAVE_DIR, local_save_dir)
        self.set_value(config.JSON_KEY_REMOTE_SAVE_DIR, remote_save_dir)

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
        exit_on_failure = False):
        return serialization.read_json_file(
            src = self.get_json_file(),
            verbose = verbose,
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
        exit_on_failure = False):
        return jsondata.JsonData(
            json_data = self.read_raw_json_data(
                verbose = verbose,
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
        return jsondata.JsonData(self.get_subvalue(key, subkey, default_value))

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
        return isinstance(self.get_value(config.JSON_KEY_METADATA), metadataentry.MetadataEntry)

    # Get metadata
    def get_metadata(self):
        if self.has_metadata():
            return self.get_value(config.JSON_KEY_METADATA)
        return None

    # Set metadata
    def set_metadata(self, metadata_value):
        return self.set_value(config.JSON_KEY_METADATA, metadata_value)

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
        return self.get_metadata_value(config.METADATA_KEY_COOP) == "Yes"

    # Check if playable
    def is_playable(self):
        return self.get_metadata_value(config.METADATA_KEY_PLAYABLE) == "Yes"

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
        return self.get_value(config.JSON_KEY_LAUNCH_NAME)

    # Get launch file
    def get_launch_file(self):
        return self.get_value(config.JSON_KEY_LAUNCH_FILE)

    # Get launch dir
    def get_launch_dir(self):
        return self.get_value(config.JSON_KEY_LAUNCH_DIR)

    # Get transform file
    def get_transform_file(self):
        return self.get_value(config.JSON_KEY_TRANSFORM_FILE)

    # Get key file
    def get_key_file(self):
        return self.get_value(config.JSON_KEY_KEY_FILE)

    # Get files
    def get_files(self, extension = None):
        files = self.get_value(config.JSON_KEY_FILES)
        if not files:
            return []
        if isinstance(extension, str):
            return [file for file in files if file.lower().endswith(extension.lower())]
        if isinstance(extension, (list, tuple)):
            return [file for file in files if any(file.lower().endswith(ext.lower()) for ext in extension)]
        return files

    # Get dlc
    def get_dlc(self):
        return self.get_value(config.JSON_KEY_DLC)

    # Get updates
    def get_updates(self):
        return self.get_value(config.JSON_KEY_UPDATE)

    # Get extras
    def get_extras(self):
        return self.get_value(config.JSON_KEY_EXTRA)

    # Get dependencies
    def get_dependencies(self):
        return self.get_value(config.JSON_KEY_DEPENDENCIES)

    ##############################

    # Get save dir
    def get_save_dir(self):
        return self.get_value(config.JSON_KEY_SAVE_DIR)

    # Get general save dir
    def get_general_save_dir(self):
        return self.get_value(config.JSON_KEY_GENERAL_SAVE_DIR)

    # Get local cache dir
    def get_local_cache_dir(self):
        return self.get_value(config.JSON_KEY_LOCAL_CACHE_DIR)

    # Get remote cache dir
    def get_remote_cache_dir(self):
        return self.get_value(config.JSON_KEY_REMOTE_CACHE_DIR)

    # Get local rom dir
    def get_local_rom_dir(self):
        return self.get_value(config.JSON_KEY_LOCAL_ROM_DIR)

    # Get remote rom dir
    def get_remote_rom_dir(self):
        return self.get_value(config.JSON_KEY_REMOTE_ROM_DIR)

    # Get local save dir
    def get_local_save_dir(self):
        return self.get_value(config.JSON_KEY_LOCAL_SAVE_DIR)

    # Get remote save dir
    def get_remote_save_dir(self):
        return self.get_value(config.JSON_KEY_REMOTE_SAVE_DIR)

    # Get rom dir by locker type
    def get_rom_dir(self, locker_type):
        if locker_type == config.LockerType.LOCAL:
            return self.get_local_rom_dir()
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
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_APPID)
    def set_store_appid(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_APPID, value)

    # Get store appname
    def get_store_appname(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_APPNAME)
    def set_store_appname(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_APPNAME, value)

    # Get store appurl
    def get_store_appurl(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_APPURL)
    def set_store_appurl(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_APPURL, value)

    # Get store branchid
    def get_store_branchid(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_BRANCHID)
    def set_store_branchid(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_BRANCHID, value)

    # Get store builddate
    def get_store_builddate(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_BUILDDATE)
    def set_store_builddate(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_BUILDDATE, value)

    # Get store buildid
    def get_store_buildid(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_BUILDID)
    def set_store_buildid(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_BUILDID, value)

    # Get store name
    def get_store_name(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_NAME)
    def set_store_name(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_NAME, value)

    # Get store controller support
    def get_store_controller_support(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_CONTROLLER_SUPPORT)
    def set_store_controller_support(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_CONTROLLER_SUPPORT, value)

    # Get store installdir
    def get_store_installdir(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_INSTALLDIR)
    def set_store_installdir(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_INSTALLDIR, value)

    # Get store paths
    def get_store_paths(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_PATHS, [])
    def set_store_paths(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_PATHS, value)

    # Get store keys
    def get_store_keys(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_KEYS, [])
    def set_store_keys(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_KEYS, value)

    # Get store launch
    def get_store_launch(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_LAUNCH, [])
    def get_store_launch_programs(self, store_key = None):
        return [computer.Program(p) for p in self.get_store_launch(store_key)]
    def set_store_launch(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_LAUNCH, value)
    def set_store_launch_programs(self, value, store_key = None):
        self.set_store_launch([v.get_data() for v in value], store_key)

    # Get store setup
    def get_store_setup(self, store_key = None):
        return self.get_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_SETUP, {})
    def set_store_setup(self, value, store_key = None):
        self.set_subvalue(store_key if store_key else self.get_main_store_key(), config.JSON_KEY_STORE_SETUP, value)

    # Get store setup install
    def get_store_setup_install(self, store_key = None):
        return self.get_store_setup(store_key).get(config.JSON_KEY_STORE_SETUP_INSTALL, [])
    def get_store_setup_install_programs(self, store_key = None):
        return [computer.Program(p) for p in self.get_store_setup_install(store_key)]

    # Get store setup preinstall
    def get_store_setup_preinstall(self, store_key = None):
        return self.get_store_setup(store_key).get(config.JSON_KEY_STORE_SETUP_PREINSTALL, [])
    def get_store_setup_preinstall_steps(self, store_key = None):
        return [computer.ProgramStep(p) for p in self.get_store_setup_preinstall(store_key)]

    # Get store setup postinstall
    def get_store_setup_postinstall(self, store_key = None):
        return self.get_store_setup(store_key).get(config.JSON_KEY_STORE_SETUP_POSTINSTALL, [])
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
                path_to_add = paths.normalize_file_path(relative_path, separator = config.OS_PATHSEP)
                should_ignore = False
                for ignore_path in config.ignored_paths_install:
                    if path_to_add.startswith(ignore_path):
                        should_ignore = True
                        break
                if should_ignore:
                    continue
                runnable_files_likely.append(path_to_add)

            # Add to launch programs
            for runnable_file_likely in runnable_files_likely:
                runnable_program = computer.Program()
                runnable_program.set_exe(paths.get_filename_file(runnable_file_likely))
                runnable_program.set_cwd(paths.get_filename_directory(runnable_file_likely))
                launch_programs.append(runnable_program)

            # Try to record these for later
            self.set_store_launch_programs(launch_programs, store_key)
            self.update_json_file()

        # Get launch info
        def get_launch_info(game_exe):
            for candidate in launch_programs:
                if paths.join_paths(candidate.get_cwd(), candidate.get_exe()) == game_exe:
                    return candidate
            return None

        # Check that we have something to run
        if len(launch_programs) == 0:
            gui.display_error_popup(
                title_text = "No runnable files",
                message_text = "Computer install has no runnable files")
            return None

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

    # Find store matching programs
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

# Derive game categories from file
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
