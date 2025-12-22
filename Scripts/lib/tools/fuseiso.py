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
    def get_name(self):
        return "FuseISO"

    # Get config
    def get_config(self):

        # Get python info
        fuseiso_exe = ini.get_ini_value("Tools.FuseISO", "fuseiso_exe")
        fusermount_exe = ini.get_ini_value("Tools.FuseISO", "fusermount_exe")
        fuseiso_install_dir = ini.get_ini_value("Tools.FuseISO", "fuseiso_install_dir")
        fusermount_install_dir = ini.get_ini_value("Tools.FuseISO", "fusermount_install_dir")

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
