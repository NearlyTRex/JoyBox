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

# Gpg tool
class Gpg(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Gpg"

    # Get config
    def get_config(self):

        # Get gpg info
        gpg_exe = ini.GetIniValue("Tools.Gpg", "gpg_exe")
        gpg_install_dir = ini.GetIniPathValue("Tools.Gpg", "gpg_install_dir")

        # Return config
        return {
            "Gpg": {
                "program": paths.join_paths(gpg_install_dir, gpg_exe)
            }
        }
