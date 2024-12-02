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

# Nile tool
class Nile(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Nile"

    # Get config
    def GetConfig(self):
        return {
            "Nile": {
                "program": "Nile/lib/main.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("Nile"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Nile",
                output_dir = programs.GetLibraryInstallDir("Nile", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Nile")
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Nile",
                output_dir = programs.GetLibraryBackupDir("Nile", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Nile")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("Nile"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("Nile", "lib"),
                install_name = "Nile",
                install_dir = programs.GetLibraryInstallDir("Nile", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Nile")
