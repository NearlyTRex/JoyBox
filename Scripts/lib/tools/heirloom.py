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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.ShouldLibraryBeInstalled("Heirloom"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Heirloom",
                output_dir = programs.GetLibraryInstallDir("Heirloom", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Heirloom")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Heirloom",
                output_dir = programs.GetLibraryBackupDir("Heirloom", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Heirloom")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("Heirloom"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("Heirloom", "lib"),
                install_name = "Heirloom",
                install_dir = programs.GetLibraryInstallDir("Heirloom", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Heirloom")
                return False
        return True
