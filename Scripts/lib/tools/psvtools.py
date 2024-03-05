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

# PSVTools tool
class PSVTools(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "PSVTools"

    # Get config
    def GetConfig(self):
        return {
            "PSVTools": {
                "program": "PSVTools/main.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("PSVTools"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PSVTools",
                output_dir = programs.GetLibraryInstallDir("PSVTools"),
                clean = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup PSVTools")
