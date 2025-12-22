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

# Phoenix emulator
class Phoenix(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Phoenix"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
        return {
            "Phoenix": {
                "program": {
                    "windows": "Phoenix/windows/PhoenixEmuProject.exe",
                    "linux": "Phoenix/windows/PhoenixEmuProject.exe"
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
        if programs.should_program_be_installed("Phoenix", "windows"):
            success = release.download_general_release(
                archive_url = "https://archive.org/download/PHX_EMU/ph28jag-win64.zip",
                search_file = "PhoenixEmuProject.exe",
                install_name = "Phoenix",
                install_dir = programs.get_program_install_dir("Phoenix", "windows"),
                backups_dir = programs.get_program_backup_dir("Phoenix", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Phoenix")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Phoenix", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Phoenix", "windows"),
                install_name = "Phoenix",
                install_dir = programs.get_program_install_dir("Phoenix", "windows"),
                search_file = "PhoenixEmuProject.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Phoenix")
                return False
        return True
