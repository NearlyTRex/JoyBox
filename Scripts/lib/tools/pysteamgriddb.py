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
    def get_name(self):
        return "PySteamGridDB"

    # Get config
    def get_config(self):
        return {
            "PySteamGridDB": {
                "package_dir": "PySteamGridDB/lib",
                "package_name": "steamgrid"
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("PySteamGridDB"):
            success = network.download_github_repository(
                github_user = "NearlyTRex",
                github_repo = "PySteamGridDB",
                output_dir = programs.get_library_install_dir("PySteamGridDB", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PySteamGridDB")
                return False
            success = network.archive_github_repository(
                github_user = "NearlyTRex",
                github_repo = "PySteamGridDB",
                output_dir = programs.get_library_backup_dir("PySteamGridDB", "lib"),
                recursive = True,
                clean = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PySteamGridDB")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("PySteamGridDB"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("PySteamGridDB", "lib"),
                install_name = "PySteamGridDB",
                install_dir = programs.get_library_install_dir("PySteamGridDB", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PySteamGridDB")
                return False
        return True
