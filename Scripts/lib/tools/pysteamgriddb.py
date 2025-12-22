# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import network
import release
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
                "package_dir": "PySteamGridDB/lib",
                "package_name": "steamgrid"
            }
        }

    # Setup
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.ShouldLibraryBeInstalled("PySteamGridDB"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PySteamGridDB",
                output_dir = programs.GetLibraryInstallDir("PySteamGridDB", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PySteamGridDB")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PySteamGridDB",
                output_dir = programs.GetLibraryBackupDir("PySteamGridDB", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PySteamGridDB")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("PySteamGridDB"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("PySteamGridDB", "lib"),
                install_name = "PySteamGridDB",
                install_dir = programs.GetLibraryInstallDir("PySteamGridDB", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PySteamGridDB")
                return False
        return True
