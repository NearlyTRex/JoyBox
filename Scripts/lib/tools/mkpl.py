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
    def get_name(self):
        return "Mkpl"

    # Get config
    def get_config(self):
        return {
            "Mkpl": {
                "program": "Mkpl/lib/mkpl.py"
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("Mkpl"):
            success = network.download_github_repository(
                github_user = "NearlyTRex",
                github_repo = "Mkpl",
                output_dir = programs.get_library_install_dir("Mkpl", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mkpl")
                return False
            success = network.archive_github_repository(
                github_user = "NearlyTRex",
                github_repo = "Mkpl",
                output_dir = programs.get_library_backup_dir("Mkpl", "lib"),
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
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("Mkpl"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("Mkpl", "lib"),
                install_name = "Mkpl",
                install_dir = programs.get_library_install_dir("Mkpl", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mkpl")
                return False
        return True
