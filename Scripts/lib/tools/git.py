# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import ini

# Local imports
from . import base

# Git tool
class Git(base.ToolBase):

    # Get name
    def GetName(self):
        return "Git"

    # Get config
    def GetConfig(self):

        # Get git info
        git_exe = ini.GetIniValue("Tools.Git", "git_exe")
        git_install_dir = ini.GetIniValue("Tools.Git", "git_install_dir")

        # Return config
        return {
            "Git": {
                "program": os.path.join(git_install_dir, git_exe)
            }
        }
