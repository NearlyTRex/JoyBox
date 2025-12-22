# Imports
import os, os.path
import sys

# Local imports
import system
import environment
import toolbase
import ini
import paths

# Config files
config_files = {}

# Wine tool
class Wine(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Wine"

    # Get config
    def get_config(self):

        # Check platform
        if not environment.is_wine_platform():
            return {}

        # Get wine info
        wine_exe = ini.get_ini_value("Tools.Wine", "wine_exe")
        wine_boot_exe = ini.get_ini_value("Tools.Wine", "wine_boot_exe")
        wine_server_exe = ini.get_ini_value("Tools.Wine", "wine_server_exe")
        wine_tricks_exe = ini.get_ini_value("Tools.Wine", "wine_tricks_exe")
        wine_install_dir = ini.get_ini_path_value("Tools.Wine", "wine_install_dir")
        wine_sandbox_dir = ini.get_ini_path_value("Tools.Wine", "wine_sandbox_dir")

        # Return config
        return {

            # Wine
            "Wine": {
                "program": paths.join_paths(wine_install_dir, wine_exe),
                "sandbox_dir": wine_sandbox_dir
            },

            # WineBoot
            "WineBoot": {
                "program": paths.join_paths(wine_install_dir, wine_boot_exe)
            },

            # WineServer
            "WineServer": {
                "program": paths.join_paths(wine_install_dir, wine_server_exe)
            },

            # WineTricks
            "WineTricks": {
                "program": paths.join_paths(wine_install_dir, wine_tricks_exe)
            }
        }
