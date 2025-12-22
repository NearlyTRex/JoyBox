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

# Chrome tool
class Chrome(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Chrome"

    # Get config
    def get_config(self):

        # Get chrome info
        chrome_exe = ini.get_ini_value("Tools.Chrome", "chrome_exe")
        chrome_install_dir = ini.get_ini_path_value("Tools.Chrome", "chrome_install_dir")
        chrome_download_dir = ini.get_ini_path_value("Tools.Chrome", "chrome_download_dir")

        # Return config
        return {
            "Chrome": {
                "program": paths.join_paths(chrome_install_dir, chrome_exe),
                "download_dir": chrome_download_dir
            }
        }
