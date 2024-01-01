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

# Mkpl tool
class Mkpl(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Mkpl"

    # Get config
    def GetConfig(self):
        return {
            "Mkpl": {
                "program": "Mkpl/mkpl.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("Mkpl"):
            success = network.DownloadLatestGithubSource(
                github_user = "NearlyTRex",
                github_repo = "Mkpl",
                output_dir = programs.GetLibraryInstallDir("Mkpl"),
                clean_first = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mkpl")
