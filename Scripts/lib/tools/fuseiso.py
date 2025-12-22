# Imports
import os, os.path
import sys

# Local imports
import config
import system
import toolbase
import ini
import paths

# Config files
config_files = {}

# FuseISO tool
class FuseISO(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "FuseISO"

    # Get config
    def GetConfig(self):

        # Get python info
        fuseiso_exe = ini.GetIniValue("Tools.FuseISO", "fuseiso_exe")
        fusermount_exe = ini.GetIniValue("Tools.FuseISO", "fusermount_exe")
        fuseiso_install_dir = ini.GetIniValue("Tools.FuseISO", "fuseiso_install_dir")
        fusermount_install_dir = ini.GetIniValue("Tools.FuseISO", "fusermount_install_dir")

        # Return config
        return {

            # FuseISO
            "FuseISO": {
                "program": {
                    "windows": None,
                    "linux": paths.join_paths(fuseiso_install_dir, fuseiso_exe)
                }
            },

            # FUserMount
            "FUserMount": {
                "program": {
                    "windows": None,
                    "linux": paths.join_paths(fusermount_install_dir, fusermount_exe)
                }
            }
        }
