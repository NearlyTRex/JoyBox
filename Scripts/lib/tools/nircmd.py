# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import release
import programs
import toolbase

# Config files
config_files = {}

# NirCmd tool
class NirCmd(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "NirCmd"

    # Get config
    def get_config(self):
        return {
            "NirCmd": {
                "program": {
                    "windows": "NirCmd/windows/nircmdc.exe",
                    "linux": "NirCmd/windows/nircmdc.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("NirCmd", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://www.nirsoft.net/utils/nircmd-x64.zip",
                search_file = "nircmdc.exe",
                install_name = "NirCmd",
                install_dir = programs.get_program_install_dir("NirCmd", "windows"),
                backups_dir = programs.get_program_backup_dir("NirCmd", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup NirCmd")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("NirCmd", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("NirCmd", "windows"),
                install_name = "NirCmd",
                install_dir = programs.get_program_install_dir("NirCmd", "windows"),
                search_file = "nircmdc.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup NirCmd")
                return False
        return True
