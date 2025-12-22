# Imports
import os, os.path
import sys

# Local imports
import system
import toolbase
import ini
import paths

# Config files
config_files = {}

# Steam tool
class Steam(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Steam"

    # Get config
    def get_config(self):

        # Get steam info
        steam_exe = ini.GetIniValue("Tools.Steam", "steam_exe")
        steam_install_dir = ini.GetIniPathValue("Tools.Steam", "steam_install_dir")

        # Return config
        return {

            # Steam
            "Steam": {
                "program": paths.join_paths(steam_install_dir, steam_exe)
            }
        }
