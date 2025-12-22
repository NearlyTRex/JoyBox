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

# Legendary tool
class Legendary(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Legendary"

    # Get config
    def get_config(self):
        return {
            "Legendary": {
                "program": "Legendary/lib/main.py"
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("Legendary"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Legendary",
                output_dir = programs.get_library_install_dir("Legendary", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Legendary")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Legendary",
                output_dir = programs.get_library_backup_dir("Legendary", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Legendary")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("Legendary"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_library_backup_dir("Legendary", "lib"),
                install_name = "Legendary",
                install_dir = programs.get_library_install_dir("Legendary", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Legendary")
                return False
        return True
