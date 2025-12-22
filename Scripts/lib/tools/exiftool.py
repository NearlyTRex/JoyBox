# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import network
import programs
import release
import toolbase

# Config files
config_files = {}

# ExifTool tool
class ExifTool(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "ExifTool"

    # Get config
    def get_config(self):
        return {
            "ExifTool": {
                "program": "ExifTool/lib/exiftool"
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("ExifTool"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "ExifTool",
                output_dir = programs.get_library_install_dir("ExifTool", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ExifTool")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "ExifTool",
                output_dir = programs.get_library_backup_dir("ExifTool", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ExifTool")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("ExifTool"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_library_backup_dir("ExifTool", "lib"),
                install_name = "ExifTool",
                install_dir = programs.get_library_install_dir("ExifTool", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ExifTool")
                return False
        return True
