# Imports
import os, os.path
import sys

# Local imports
import ini
import toolbase

# Git tool
class Git(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Git"

    # Get config
    def GetConfig(self):

        # Get git info
        git_exe = ini.GetIniValue("Tools.Git", "git_exe")
        git_install_dir = ini.GetIniPathValue("Tools.Git", "git_install_dir")

        # Return config
        return {
            "Git": {
                "program": os.path.join(git_install_dir, git_exe)
            }
        }
