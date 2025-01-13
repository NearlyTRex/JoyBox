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

# ItchDL tool
class ItchDL(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "ItchDL"

    # Get config
    def GetConfig(self):
        return {
            "ItchDL": {
                "program": "ItchDL/lib/itch_dl/cli.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("ItchDL"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "ItchDL",
                output_dir = programs.GetLibraryInstallDir("ItchDL", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ItchDL")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "ItchDL",
                output_dir = programs.GetLibraryBackupDir("ItchDL", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ItchDL")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("ItchDL"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("ItchDL", "lib"),
                install_name = "ItchDL",
                install_dir = programs.GetLibraryInstallDir("ItchDL", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ItchDL")
                return False
        return True
