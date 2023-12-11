# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import ini

# Local imports
from . import base

# Firefox tool
class Firefox(base.ToolBase):

    # Get name
    def GetName(self):
        return "Firefox"

    # Get config
    def GetConfig(self):

        # Get firefox info
        firefox_exe = ini.GetIniValue("Tools.Firefox", "firefox_exe")
        firefox_install_dir = ini.GetIniValue("Tools.Firefox", "firefox_install_dir")

        # Return config
        return {
            "Firefox": {
                "program": os.path.join(firefox_install_dir, firefox_exe)
            }
        }
