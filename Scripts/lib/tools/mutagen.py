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

# Mutagen tool
class Mutagen(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Mutagen"

    # Get config
    def GetConfig(self):
        return {
            "Mutagen": {
                "program": "Mutagen/lib/mutagen/__init__.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("Mutagen"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Mutagen",
                output_dir = programs.GetLibraryInstallDir("Mutagen", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Mutagen")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Mutagen",
                output_dir = programs.GetLibraryBackupDir("Mutagen", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Mutagen")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("Mutagen"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("Mutagen", "lib"),
                install_name = "Mutagen",
                install_dir = programs.GetLibraryInstallDir("Mutagen", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Mutagen")
                return False
        return True
