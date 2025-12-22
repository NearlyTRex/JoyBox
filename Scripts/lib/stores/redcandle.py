# Imports
import os, os.path
import sys
import json

# Local imports
import config
import system
import ini
import storebase
import metadatacollector
import paths

# RedCandle store
class RedCandle(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.RedCandle", "redcandle_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def get_name(self):
        return config.StoreType.RED_CANDLE.val()

    # Get type
    def get_type(self):
        return config.StoreType.RED_CANDLE

    # Get platform
    def get_platform(self):
        return config.Platform.COMPUTER_RED_CANDLE

    # Get supercategory
    def get_supercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def get_category(self):
        return config.Category.COMPUTER

    # Get subcategory
    def get_subcategory(self):
        return config.Subcategory.COMPUTER_RED_CANDLE

    # Get key
    def get_key(self):
        return config.json_key_redcandle

    # Get identifier keys
    def get_identifier_keys(self):
        return {
            config.StoreIdentifierType.INFO: config.json_key_store_name,
            config.StoreIdentifierType.INSTALL: config.json_key_store_name,
            config.StoreIdentifierType.LAUNCH: config.json_key_store_name,
            config.StoreIdentifierType.DOWNLOAD: config.json_key_store_name,
            config.StoreIdentifierType.ASSET: config.json_key_store_name,
            config.StoreIdentifierType.METADATA: config.json_key_store_name,
            config.StoreIdentifierType.PAGE: config.json_key_store_name
        }

    # Get install dir
    def get_install_dir(self):
        return self.install_dir

    ############################################################
