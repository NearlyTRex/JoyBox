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

# PySteamGridDB tool
class PySteamGridDB(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "PySteamGridDB"

    # Get config
    def GetConfig(self):
        return {
            "PySteamGridDB": {
                "package_dir": "PySteamGridDB/lib/steamgrid"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("PySteamGridDB"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PySteamGridDB",
                output_dir = programs.GetLibraryInstallDir("PySteamGridDB", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup PySteamGridDB")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PySteamGridDB",
                output_dir = programs.GetLibraryBackupDir("PySteamGridDB", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup PySteamGridDB")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("PySteamGridDB"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("PySteamGridDB", "lib"),
                install_name = "PySteamGridDB",
                install_dir = programs.GetLibraryInstallDir("PySteamGridDB", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup PySteamGridDB")
                return False
        return True
