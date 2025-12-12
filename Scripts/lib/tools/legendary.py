# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import release
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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.ShouldLibraryBeInstalled("Legendary"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Legendary",
                output_dir = programs.GetLibraryInstallDir("Legendary", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Legendary")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Legendary",
                output_dir = programs.GetLibraryBackupDir("Legendary", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Legendary")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("Legendary"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("Legendary", "lib"),
                install_name = "Legendary",
                install_dir = programs.GetLibraryInstallDir("Legendary", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Legendary")
                return False
        return True
