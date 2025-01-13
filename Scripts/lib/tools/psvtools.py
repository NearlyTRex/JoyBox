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

# PSVTools tool
class PSVTools(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "PSVTools"

    # Get config
    def GetConfig(self):
        return {
            "PSVTools": {
                "program": "PSVTools/lib/main.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("PSVTools"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PSVTools",
                output_dir = programs.GetLibraryInstallDir("PSVTools", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
				system.LogError("Could not setup PSVTools")
				return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PSVTools",
                output_dir = programs.GetLibraryBackupDir("PSVTools", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
				system.LogError("Could not setup PSVTools")
				return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("PSVTools"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("PSVTools", "lib"),
                install_name = "PSVTools",
                install_dir = programs.GetLibraryInstallDir("PSVTools", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
				system.LogError("Could not setup PSVTools")
				return False
        return True
