# Imports
import os, os.path
import sys

# Local imports
import system
import toolbase
import ini
import paths

# Config files
config_files = {}

# Git tool
class Git(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Git"

    # Get config
    def get_config(self):

        # Get git info
        git_exe = ini.GetIniValue("Tools.Git", "git_exe")
        git_install_dir = ini.GetIniPathValue("Tools.Git", "git_install_dir")

        # Return config
        return {
            "Git": {
                "program": paths.join_paths(git_install_dir, git_exe)
            }
        }
