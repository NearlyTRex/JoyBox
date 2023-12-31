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

# PyLnk tool
class PyLnk(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "PyLnk"

    # Get config
    def GetConfig(self):
        return {
            "PyLnk": {
                "program": "PyLnk/pylnk3.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("PyLnk"):
            success = network.DownloadLatestGithubSource(
                github_user = "NearlyTRex",
                github_repo = "PyLnk",
                output_dir = programs.GetLibraryInstallDir("PyLnk"),
                clean_first = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup PyLnk")
