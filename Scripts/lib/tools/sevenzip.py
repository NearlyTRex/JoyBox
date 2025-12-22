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

# 7-Zip tool
class SevenZip(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "7-Zip"

    # Get config
    def GetConfig(self):

        # Get sevenzip info
        sevenzip_exe = ini.GetIniValue("Tools.7Zip", "7z_exe")
        sevenzip_install_dir = ini.GetIniPathValue("Tools.7Zip", "7z_install_dir")

        # Return config
        return {
            "7-Zip": {
                "program": paths.join_paths(sevenzip_install_dir, sevenzip_exe)
            }
        }
