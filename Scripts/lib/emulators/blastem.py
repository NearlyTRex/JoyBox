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

# BlastEm emulator
class BlastEm(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "BlastEm"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
        return {
            "BlastEm": {
                "program": {
                    "windows": "BlastEm/windows/blastem.exe",
                    "linux": "BlastEm/windows/blastem.exe"
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
        if programs.should_program_be_installed("BlastEm", "windows"):
            success = release.download_webpage_release(
                webpage_url = "https://www.retrodev.com/blastem",
                webpage_base_url = "https://www.retrodev.com/blastem",
                starts_with = "https://www.retrodev.com/blastem/blastem-win32",
                ends_with = ".zip",
                search_file = "blastem.exe",
                install_name = "BlastEm",
                install_dir = programs.get_program_install_dir("BlastEm", "windows"),
                backups_dir = programs.get_program_backup_dir("BlastEm", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BlastEm")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("BlastEm", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("BlastEm", "windows"),
                install_name = "BlastEm",
                install_dir = programs.get_program_install_dir("BlastEm", "windows"),
                search_file = "blastem.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BlastEm")
                return False
        return True
