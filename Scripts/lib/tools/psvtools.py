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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.ShouldLibraryBeInstalled("PSVTools"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PSVTools",
                output_dir = programs.GetLibraryInstallDir("PSVTools", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSVTools")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PSVTools",
                output_dir = programs.GetLibraryBackupDir("PSVTools", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSVTools")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("PSVTools"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("PSVTools", "lib"),
                install_name = "PSVTools",
                install_dir = programs.GetLibraryInstallDir("PSVTools", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSVTools")
                return False
        return True
