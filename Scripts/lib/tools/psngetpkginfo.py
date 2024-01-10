# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import programs
import toolbase

# Config files
config_files = {}

# PSNGetPkgInfo tool
class PSNGetPkgInfo(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "PSNGetPkgInfo"

    # Get config
    def GetConfig(self):
        return {
            "PSNGetPkgInfo": {
                "program": "PSNGetPkgInfo/PSN_get_pkg_info.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("PSNGetPkgInfo"):
            success = network.DownloadGithubSource(
                github_user = "NearlyTRex",
                github_repo = "PSNGetPkgInfo",
                output_dir = programs.GetLibraryInstallDir("PSNGetPkgInfo"),
                clean_first = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup PSNGetPkgInfo")
