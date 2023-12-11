# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import ini

# Local imports
from . import base

# Curl tool
class Curl(base.ToolBase):

    # Get name
    def GetName(self):
        return "Curl"

    # Get config
    def GetConfig(self):

        # Get curl info
        curl_exe = ini.GetIniValue("Tools.Curl", "curl_exe")
        curl_install_dir = ini.GetIniValue("Tools.Curl", "curl_install_dir")

        # Return config
        return {
            "Curl": {
                "program": os.path.join(curl_install_dir, curl_exe)
            }
        }
