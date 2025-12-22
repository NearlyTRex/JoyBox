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

# SteamCMD tool
class SteamCMD(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "SteamCMD"

    # Get config
    def get_config(self):

        # Get steamcmd info
        steamcmd_exe = ini.get_ini_value("Tools.Steam", "steamcmd_exe")
        steamcmd_install_dir = ini.get_ini_path_value("Tools.Steam", "steamcmd_install_dir")

        # Return config
        return {

            # SteamCMD
            "SteamCMD": {
                "program": paths.join_paths(steamcmd_install_dir, steamcmd_exe)
            }
        }
