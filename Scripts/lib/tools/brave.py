# Imports
import os, os.path
import sys

# Local imports
import ini
import toolbase

# Config files
config_files = {}

# Brave tool
class Brave(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Brave"

    # Get config
    def GetConfig(self):

        # Get brave info
        brave_exe = ini.GetIniValue("Tools.Brave", "brave_exe")
        brave_install_dir = ini.GetIniPathValue("Tools.Brave", "brave_install_dir")
        brave_download_dir = ini.GetIniPathValue("Tools.Brave", "brave_download_dir")

        # Return config
        return {
            "Brave": {
                "program": os.path.join(brave_install_dir, brave_exe),
                "download_dir": brave_download_dir
            }
        }
