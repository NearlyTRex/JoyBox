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

# PySimpleGUI tool
class PySimpleGUI(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "PySimpleGUI"

    # Get config
    def GetConfig(self):
        return {
            "PySimpleGUI": {
                "program": "PySimpleGUI/PySimpleGUI.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("PySimpleGUI"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PySimpleGUI",
                output_dir = programs.GetLibraryInstallDir("PySimpleGUI"),
                clean = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup PySimpleGUI")

