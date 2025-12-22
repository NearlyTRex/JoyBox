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

# HumbleBundleManager tool
class HumbleBundleManager(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "HumbleBundleManager"

    # Get config
    def get_config(self):
        return {
            "HumbleBundleManager": {
                "program": "HumbleBundleManager/lib/humblebundle.py"
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.ShouldLibraryBeInstalled("HumbleBundleManager"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "HumbleBundleManager",
                output_dir = programs.GetLibraryInstallDir("HumbleBundleManager", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup HumbleBundleManager")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "HumbleBundleManager",
                output_dir = programs.GetLibraryBackupDir("HumbleBundleManager", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup HumbleBundleManager")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("HumbleBundleManager"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("HumbleBundleManager", "lib"),
                install_name = "HumbleBundleManager",
                install_dir = programs.GetLibraryInstallDir("HumbleBundleManager", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup HumbleBundleManager")
                return False
        return True
