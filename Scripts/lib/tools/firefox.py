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

# Firefox tool
class Firefox(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Firefox"

    # Get config
    def GetConfig(self):

        # Get firefox info
        firefox_exe = ini.GetIniValue("Tools.Firefox", "firefox_exe")
        firefox_install_dir = ini.GetIniPathValue("Tools.Firefox", "firefox_install_dir")
        firefox_download_dir = ini.GetIniPathValue("Tools.Firefox", "firefox_download_dir")
        firefox_profile_dir = ini.GetIniPathValue("Tools.Firefox", "firefox_profile_dir")

        # Return config
        return {
            "Firefox": {
                "program": paths.join_paths(firefox_install_dir, firefox_exe),
                "download_dir": firefox_download_dir,
                "profile_dir": firefox_profile_dir
            }
        }
