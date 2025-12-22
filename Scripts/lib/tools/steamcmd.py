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
    def GetName(self):
        return "SteamCMD"

    # Get config
    def GetConfig(self):

        # Get steamcmd info
        steamcmd_exe = ini.GetIniValue("Tools.Steam", "steamcmd_exe")
        steamcmd_install_dir = ini.GetIniPathValue("Tools.Steam", "steamcmd_install_dir")

        # Return config
        return {

            # SteamCMD
            "SteamCMD": {
                "program": paths.join_paths(steamcmd_install_dir, steamcmd_exe)
            }
        }
