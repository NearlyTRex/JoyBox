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

# SquareEnix store
class SquareEnix(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.SquareEnix", "squareenix_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def GetName(self):
        return config.StoreType.SQUARE_ENIX.val()

    # Get type
    def GetType(self):
        return config.StoreType.SQUARE_ENIX

    # Get platform
    def GetPlatform(self):
        return config.Platform.COMPUTER_SQUARE_ENIX

    # Get supercategory
    def GetSupercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def GetCategory(self):
        return config.Category.COMPUTER

    # Get subcategory
    def GetSubcategory(self):
        return config.Subcategory.COMPUTER_SQUARE_ENIX

    # Get key
    def GetKey(self):
        return config.json_key_squareenix

    # Get identifier keys
    def GetIdentifierKeys(self):
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
