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
                "program": "PyLnk/lib/pylnk3.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("PyLnk"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PyLnk",
                output_dir = programs.GetLibraryInstallDir("PyLnk", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup PyLnk")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PyLnk",
                output_dir = programs.GetLibraryBackupDir("PyLnk", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup PyLnk")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("PyLnk"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("PyLnk", "lib"),
                install_name = "PyLnk",
                install_dir = programs.GetLibraryInstallDir("PyLnk", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup PyLnk")
                return False
        return True
