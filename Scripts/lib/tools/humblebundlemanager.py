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

# HumbleBundleManager tool
class HumbleBundleManager(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "HumbleBundleManager"

    # Get config
    def GetConfig(self):
        return {
            "HumbleBundleManager": {
                "program": "HumbleBundleManager/lib/humblebundle.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("HumbleBundleManager"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "HumbleBundleManager",
                output_dir = programs.GetLibraryInstallDir("HumbleBundleManager", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup HumbleBundleManager")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "HumbleBundleManager",
                output_dir = programs.GetLibraryBackupDir("HumbleBundleManager", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup HumbleBundleManager")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("HumbleBundleManager"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("HumbleBundleManager", "lib"),
                install_name = "HumbleBundleManager",
                install_dir = programs.GetLibraryInstallDir("HumbleBundleManager", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup HumbleBundleManager")
                return False
        return True
