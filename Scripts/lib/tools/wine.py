# Imports
import os, os.path
import sys

# Local imports
import environment
import ini
import toolbase

# Wine tool
class Wine(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Wine"

    # Get config
    def GetConfig(self):

        # Check platform
        if not environment.IsWinePlatform():
            return {}

        # Get wine info
        wine_exe = ini.GetIniValue("Tools.Wine", "wine_exe")
        wine_boot_exe = ini.GetIniValue("Tools.Wine", "wine_boot_exe")
        wine_server_exe = ini.GetIniValue("Tools.Wine", "wine_server_exe")
        wine_tricks_exe = ini.GetIniValue("Tools.Wine", "wine_tricks_exe")
        wine_install_dir = ini.GetIniPathValue("Tools.Wine", "wine_install_dir")
        wine_sandbox_dir = ini.GetIniPathValue("Tools.Wine", "wine_sandbox_dir")

        # Return config
        return {

            # Wine
            "Wine": {
                "program": os.path.join(wine_install_dir, wine_exe),
                "sandbox_dir": wine_sandbox_dir
            },

            # WineBoot
            "WineBoot": {
                "program": os.path.join(wine_install_dir, wine_boot_exe)
            },

            # WineServer
            "WineServer": {
                "program": os.path.join(wine_install_dir, wine_server_exe)
            },

            # WineTricks
            "WineTricks": {
                "program": os.path.join(wine_install_dir, wine_tricks_exe)
            }
        }
