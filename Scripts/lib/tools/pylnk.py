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

# PyLnk tool
class PyLnk(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "PyLnk"

    # Get config
    def get_config(self):
        return {
            "PyLnk": {
                "program": "PyLnk/lib/pylnk3.py"
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("PyLnk"):
            success = network.download_github_repository(
                github_user = "NearlyTRex",
                github_repo = "PyLnk",
                output_dir = programs.get_library_install_dir("PyLnk", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PyLnk")
                return False
            success = network.archive_github_repository(
                github_user = "NearlyTRex",
                github_repo = "PyLnk",
                output_dir = programs.get_library_backup_dir("PyLnk", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PyLnk")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("PyLnk"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("PyLnk", "lib"),
                install_name = "PyLnk",
                install_dir = programs.get_library_install_dir("PyLnk", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PyLnk")
                return False
        return True
