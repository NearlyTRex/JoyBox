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
                "program": "PySimpleGUI/lib/PySimpleGUI.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("PySimpleGUI"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PySimpleGUI",
                output_dir = programs.GetLibraryInstallDir("PySimpleGUI", "lib"),
                clean = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup PySimpleGUI")
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PySimpleGUI",
                output_dir = programs.GetLibraryBackupDir("PySimpleGUI", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup PySimpleGUI")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):
        pass

