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

# Mkpl tool
class Mkpl(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Mkpl"

    # Get config
    def GetConfig(self):
        return {
            "Mkpl": {
                "program": "Mkpl/lib/mkpl.py"
            }
        }

    # Setup
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.ShouldLibraryBeInstalled("Mkpl"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Mkpl",
                output_dir = programs.GetLibraryInstallDir("Mkpl", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mkpl")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Mkpl",
                output_dir = programs.GetLibraryBackupDir("Mkpl", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mkpl")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("Mkpl"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("Mkpl", "lib"),
                install_name = "Mkpl",
                install_dir = programs.GetLibraryInstallDir("Mkpl", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mkpl")
                return False
        return True
