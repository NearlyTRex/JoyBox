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
    def get_name(self):
        return "Firefox"

    # Get config
    def get_config(self):

        # Get firefox info
        firefox_exe = ini.get_ini_value("Tools.Firefox", "firefox_exe")
        firefox_install_dir = ini.get_ini_path_value("Tools.Firefox", "firefox_install_dir")
        firefox_download_dir = ini.get_ini_path_value("Tools.Firefox", "firefox_download_dir")
        firefox_profile_dir = ini.get_ini_path_value("Tools.Firefox", "firefox_profile_dir")

        # Return config
        return {
            "Firefox": {
                "program": paths.join_paths(firefox_install_dir, firefox_exe),
                "download_dir": firefox_download_dir,
                "profile_dir": firefox_profile_dir
            }
        }
