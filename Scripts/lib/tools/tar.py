# Imports
import os, os.path
import sys

# Local imports
import ini
import toolbase

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
                "program": os.path.join(tar_install_dir, tar_exe)
            }
        }
