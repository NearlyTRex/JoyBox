# Imports
import os, os.path
import sys

# Local imports
import system
import toolbase
import ini

# Config files
config_files = {}

# Tar tool
class Tar(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Tar"

    # Get config
    def GetConfig(self):

        # Get tar info
        tar_exe = ini.GetIniValue("Tools.Tar", "tar_exe")
        tar_install_dir = ini.GetIniPathValue("Tools.Tar", "tar_install_dir")

        # Return config
        return {
            "Tar": {
                "program": system.JoinPaths(tar_install_dir, tar_exe)
            }
        }
