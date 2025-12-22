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
    def get_name(self):
        return "Nile"

    # Get config
    def get_config(self):
        return {
            "Nile": {
                "program": "Nile/lib/main.py"
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("Nile"):
            success = network.download_github_repository(
                github_user = "NearlyTRex",
                github_repo = "Nile",
                output_dir = programs.get_library_install_dir("Nile", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Nile")
                return False
            success = network.archive_github_repository(
                github_user = "NearlyTRex",
                github_repo = "Nile",
                output_dir = programs.get_library_backup_dir("Nile", "lib"),
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
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("Nile"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("Nile", "lib"),
                install_name = "Nile",
                install_dir = programs.get_library_install_dir("Nile", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Nile")
                return False
        return True
