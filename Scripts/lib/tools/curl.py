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

# Curl tool
class Curl(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Curl"

    # Get config
    def get_config(self):

        # Get curl info
        curl_exe = ini.get_ini_value("Tools.Curl", "curl_exe")
        curl_install_dir = ini.get_ini_path_value("Tools.Curl", "curl_install_dir")

        # Return config
        return {
            "Curl": {
                "program": paths.join_paths(curl_install_dir, curl_exe)
            }
        }
