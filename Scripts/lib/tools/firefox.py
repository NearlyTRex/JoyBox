# Imports
import os, os.path
import sys

# Local imports
import ini
import toolbase

# Firefox tool
class Firefox(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Firefox"

    # Get config
    def GetConfig(self):

        # Get firefox info
        firefox_exe = ini.GetIniValue("Tools.Firefox", "firefox_exe")
        firefox_install_dir = ini.GetIniPathValue("Tools.Firefox", "firefox_install_dir")

        # Return config
        return {
            "Firefox": {
                "program": os.path.join(firefox_install_dir, firefox_exe)
            }
        }
