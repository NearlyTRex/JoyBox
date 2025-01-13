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

# ExifTool tool
class ExifTool(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "ExifTool"

    # Get config
    def GetConfig(self):
        return {
            "ExifTool": {
                "program": "ExifTool/lib/exiftool"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("ExifTool"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "ExifTool",
                output_dir = programs.GetLibraryInstallDir("ExifTool", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
				system.LogError("Could not setup ExifTool")
				return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "ExifTool",
                output_dir = programs.GetLibraryBackupDir("ExifTool", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
				system.LogError("Could not setup ExifTool")
				return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("ExifTool"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("ExifTool", "lib"),
                install_name = "ExifTool",
                install_dir = programs.GetLibraryInstallDir("ExifTool", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
				system.LogError("Could not setup ExifTool")
				return False
        return True
