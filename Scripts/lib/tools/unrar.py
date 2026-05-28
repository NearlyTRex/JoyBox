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

# Unrar tool
class Unrar(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Unrar"

    # Get config
    def get_config(self):

        # Get unrar info
        unrar_exe = ini.get_ini_value("Tools.Unrar", "unrar_exe")
        unrar_install_dir = ini.get_ini_path_value("Tools.Unrar", "unrar_install_dir")

        # Return config
        return {
            "Unrar": {
                "program": paths.join_paths(unrar_install_dir, unrar_exe)
            }
        }
