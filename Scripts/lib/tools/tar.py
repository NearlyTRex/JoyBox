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

# Tar tool
class Tar(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Tar"

    # Get config
    def get_config(self):

        # Get tar info
        tar_exe = ini.GetIniValue("Tools.Tar", "tar_exe")
        tar_install_dir = ini.GetIniPathValue("Tools.Tar", "tar_install_dir")

        # Return config
        return {
            "Tar": {
                "program": paths.join_paths(tar_install_dir, tar_exe)
            }
        }
