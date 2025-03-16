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

# RedCandle store
class RedCandle(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.RedCandle", "redcandle_install_dir")
        if not system.IsPathValid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def GetName(self):
        return config.StoreType.RED_CANDLE.val()

    # Get type
    def GetType(self):
        return config.StoreType.RED_CANDLE

    # Get platform
    def GetPlatform(self):
        return config.Platform.COMPUTER_RED_CANDLE

    # Get supercategory
    def GetSupercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def GetCategory(self):
        return config.Category.COMPUTER

    # Get subcategory
    def GetSubcategory(self):
        return config.Subcategory.COMPUTER_RED_CANDLE

    # Get key
    def GetKey(self):
        return config.json_key_redcandle

    # Get identifier keys
    def GetIdentifierKeys():
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
    def GetInstallDir(self):
        return self.install_dir

    ############################################################
