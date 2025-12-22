# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.ShouldLibraryBeInstalled("Nile"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Nile",
                output_dir = programs.GetLibraryInstallDir("Nile", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Nile")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Nile",
                output_dir = programs.GetLibraryBackupDir("Nile", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Nile")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("Nile"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("Nile", "lib"),
                install_name = "Nile",
                install_dir = programs.GetLibraryInstallDir("Nile", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Nile")
                return False
        return True
