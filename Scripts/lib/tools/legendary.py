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

# Legendary tool
class Legendary(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Legendary"

    # Get config
    def GetConfig(self):
        return {
            "Legendary": {
                "program": "Legendary/lib/main.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("Legendary"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Legendary",
                output_dir = programs.GetLibraryInstallDir("Legendary", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Legendary")
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Legendary",
                output_dir = programs.GetLibraryBackupDir("Legendary", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Legendary")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("Legendary"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("Legendary", "lib"),
                install_name = "Legendary",
                install_dir = programs.GetLibraryInstallDir("Legendary", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Legendary")
