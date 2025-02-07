# Imports
import os, os.path
import sys
import json

# Local imports
import config
import system
import ini
import jsondata
import storebase
import metadatacollector

# Zoom store
class Zoom(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.Zoom", "zoom_install_dir")
        if not system.IsPathValid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def GetName(self):
        return config.StoreType.ZOOM.val()

    # Get type
    def GetType(self):
        return config.StoreType.ZOOM

    # Get platform
    def GetPlatform(self):
        return config.Platform.COMPUTER_ZOOM

    # Get supercategory
    def GetSupercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def GetCategory(self):
        return config.Category.COMPUTER

    # Get subcategory
    def GetSubcategory(self):
        return config.Subcategory.COMPUTER_ZOOM

    # Get key
    def GetKey(self):
        return config.json_key_zoom

    # Get identifier
    def GetIdentifier(self, json_wrapper, identifier_type):
        if identifier_type == config.StoreIdentifierType.INFO:
            return json_wrapper.get_value(config.json_key_store_name)
        elif identifier_type == config.StoreIdentifierType.ASSET:
            return json_wrapper.get_value(config.json_key_store_name)
        elif identifier_type == config.StoreIdentifierType.METADATA:
            return json_wrapper.get_value(config.json_key_store_name)
        return json_wrapper.get_value(config.json_key_store_appname)

    # Get install dir
    def GetInstallDir(self):
        return self.install_dir

    ############################################################
    # Json
    ############################################################

    # Get latest jsondata
    def GetLatestJsondata(
        self,
        identifier,
        branch = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidIdentifier(identifier):
            return None

        # Build game info
        game_info = {}
        game_info[config.json_key_store_name] = identifier
        game_info[config.json_key_store_paths] = []
        game_info[config.json_key_store_keys] = []

        # Augment by manifest
        if self.manifest:
            manifest_entry = self.manifest.find_entry_by_name(
                name = identifier,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if manifest_entry:

                # Get existing paths and keys
                game_paths = set(game_info[config.json_key_store_paths])
                game_keys = set(game_info[config.json_key_store_keys])

                # Get base path
                base_path = config.token_game_install_dir

                # Update paths and keys
                game_paths = list(game_paths.union(manifest_entry.get_paths(base_path)))
                game_keys = list(game_keys.union(manifest_entry.get_keys()))

                # Remove invalid paths
                game_paths = [item for item in game_paths if not item.startswith("C:")]
                game_paths = [item for item in game_paths if not config.token_store_install_dir in item]
                game_paths = [item for item in game_paths if not config.token_store_user_id in item]

                # Save paths and keys
                game_info[config.json_key_store_paths] = system.SortStrings(game_paths)
                game_info[config.json_key_store_keys] = system.SortStrings(game_keys)

        # Return game info
        return jsondata.JsonData(game_info, self.GetPlatform())

    ############################################################
