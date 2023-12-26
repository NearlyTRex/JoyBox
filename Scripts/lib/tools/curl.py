# Imports
import os, os.path
import sys

# Local imports
import ini
import toolbase

# Curl tool
class Curl(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Curl"

    # Get config
    def GetConfig(self):

        # Get curl info
        curl_exe = ini.GetIniValue("Tools.Curl", "curl_exe")
        curl_install_dir = ini.GetIniPathValue("Tools.Curl", "curl_install_dir")

        # Return config
        return {
            "Curl": {
                "program": os.path.join(curl_install_dir, curl_exe)
            }
        }
