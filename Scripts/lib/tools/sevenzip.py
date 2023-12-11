# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import ini

# Local imports
from . import base

# 7-Zip tool
class SevenZip(base.ToolBase):

    # Get name
    def GetName(self):
        return "7-Zip"

    # Get config
    def GetConfig(self):

        # Get git info
        sevenzip_exe = ini.GetIniValue("Tools.7Zip", "7z_exe")
        sevenzip_standalone_exe = ini.GetIniValue("Tools.7Zip", "7z_standalone_exe")
        sevenzip_install_dir = ini.GetIniValue("Tools.7Zip", "7z_install_dir")

        # Return config
        return {

            # 7-Zip
            "7-Zip": {
                "program": os.path.join(sevenzip_install_dir, sevenzip_exe)
            },

            # 7-Zip-Standalone
            "7-Zip-Standalone": {
                "program": os.path.join(sevenzip_install_dir, sevenzip_standalone_exe),
            }
        }
