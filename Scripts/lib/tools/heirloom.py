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

# Heirloom tool
class Heirloom(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Heirloom"

    # Get config
    def GetConfig(self):
        return {
            "Heirloom": {
                "program": "Heirloom/lib/main.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("Heirloom"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Heirloom",
                output_dir = programs.GetLibraryInstallDir("Heirloom", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Heirloom")
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Heirloom",
                output_dir = programs.GetLibraryBackupDir("Heirloom", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Heirloom")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("Heirloom"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("Heirloom", "lib"),
                install_name = "Heirloom",
                install_dir = programs.GetLibraryInstallDir("Heirloom", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Heirloom")
