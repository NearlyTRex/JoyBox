# Imports
import os, os.path
import sys

# Local imports
import ini
import toolbase

# XorrISO tool
class XorrISO(toolbase.ToolBase):

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
