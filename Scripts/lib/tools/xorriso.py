# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import ini

# Local imports
from . import base

# XorrISO tool
class XorrISO(base.ToolBase):

    # Get name
    def GetName(self):
        return "XorrISO"

    # Get config
    def GetConfig(self):

        # Get xorriso info
        xorriso_exe = ini.GetIniValue("Tools.XorrISO", "xorriso_exe")
        xorriso_install_dir = ini.GetIniValue("Tools.XorrISO", "xorriso_install_dir")

        # Return config
        return {
            "XorrISO": {
                "program": os.path.join(xorriso_install_dir, xorriso_exe)
            }
        }
