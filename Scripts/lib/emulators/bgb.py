# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import logger
import release
import programs
import emulatorbase

# Config files
config_files = {}

# System files
system_files = {}

# BGB emulator
class BGB(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "BGB"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
        return {
            "BGB": {
                "program": {
                    "windows": "BGB/windows/bgb.exe",
                    "linux": "BGB/windows/bgb.exe"
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
        if programs.should_program_be_installed("BGB", "windows"):
            success = release.download_general_release(
                archive_url = "https://bgb.bircd.org/bgb.zip",
                search_file = "bgb.exe",
                install_name = "BGB",
                install_dir = programs.get_program_install_dir("BGB", "windows"),
                backups_dir = programs.get_program_backup_dir("BGB", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BGB")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("BGB", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("BGB", "windows"),
                install_name = "BGB",
                install_dir = programs.get_program_install_dir("BGB", "windows"),
                search_file = "bgb.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BGB")
                return False
        return True
